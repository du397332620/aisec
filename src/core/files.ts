import { open, opendir, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { basename, extname, join } from "node:path";
import { DEFAULT_EXCLUDES, MANIFEST_NAMES, TEXT_EXTENSIONS } from "./constants.js";
import { assertPathInside, normalizeRelative } from "./utils.js";

export interface ProjectFile {
  absolutePath: string;
  relativePath: string;
  size: number;
  content: string;
}

export interface FileInventory {
  files: ProjectFile[];
  totalBytes: number;
  skippedFiles: number;
  skippedReasons: Record<string, number>;
}

const PARTIAL_INVENTORY_REASONS = new Set([
  "file_limit",
  "entry_limit",
  "total_bytes_limit",
  "directory_depth",
  "oversized_file",
  "binary_file",
  "non_regular_file",
  "unreadable_file",
  "unreadable_directory",
  "symbolic_link",
  "path_escape",
]);

export function inventoryCoverage(inventory: FileInventory): { status: "complete" | "partial"; reason?: string } {
  if (inventory.skippedFiles === 0) return { status: "complete" };
  const entries = Object.entries(inventory.skippedReasons).sort(([left], [right]) => left.localeCompare(right));
  const status = entries.some(([reason, count]) => count > 0 && PARTIAL_INVENTORY_REASONS.has(reason)) ? "partial" : "complete";
  return { status, reason: entries.map(([reason, count]) => `${reason}: ${count}`).join(", ") };
}

function isTextCandidate(name: string): boolean {
  if (MANIFEST_NAMES.has(name)) return true;
  if (name === ".aisec.yml") return true;
  if (name.startsWith(".env")) return true;
  if (name === "Dockerfile" || name.startsWith("Dockerfile.")) return true;
  return TEXT_EXTENSIONS.has(extname(name).toLowerCase());
}

export async function collectProjectFiles(
  root: string,
  options: { maxFiles: number; maxFileBytes: number; maxTotalBytes: number },
): Promise<FileInventory> {
  const files: ProjectFile[] = [];
  let totalBytes = 0;
  let skippedFiles = 0;
  let entriesSeen = 0;
  let fileLimitReached = false;
  let entryLimitReached = false;
  let totalBytesLimitReached = false;
  const entryLimit = Math.min(100_000, options.maxFiles * 5);
  const skippedReasons: Record<string, number> = {};

  const skip = (reason: string): void => {
    skippedFiles += 1;
    skippedReasons[reason] = (skippedReasons[reason] ?? 0) + 1;
  };

  async function walk(directory: string, depth = 0): Promise<void> {
    if (fileLimitReached || entryLimitReached || totalBytesLimitReached) return;
    if (depth > 64) {
      skip("directory_depth");
      return;
    }
    let handle: Awaited<ReturnType<typeof opendir>>;
    try {
      handle = await opendir(directory);
    } catch {
      skip("unreadable_directory");
      return;
    }
    const entries = [];
    for await (const entry of handle) {
      if (entriesSeen >= entryLimit) {
        entryLimitReached = true;
        skip("entry_limit");
        break;
      }
      entriesSeen += 1;
      entries.push(entry);
    }
    if (entryLimitReached) return;
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (fileLimitReached || entryLimitReached || totalBytesLimitReached) return;
      if (DEFAULT_EXCLUDES.has(entry.name)) {
        skip("excluded_directory");
        continue;
      }
      const absolutePath = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        skip("symbolic_link");
        continue;
      }
      if (entry.isDirectory()) {
        if (files.length >= options.maxFiles) {
          fileLimitReached = true;
          skip("file_limit");
          return;
        }
        await walk(absolutePath, depth + 1);
        continue;
      }
      if (!entry.isFile()) {
        skip("non_regular_file");
        continue;
      }
      if (!isTextCandidate(entry.name)) continue;
      if (files.length >= options.maxFiles) {
        fileLimitReached = true;
        skip("file_limit");
        return;
      }

      let fileHandle: Awaited<ReturnType<typeof open>> | undefined;
      try {
        // O_NOFOLLOW closes the usual Dirent-check/read race for the final path
        // component. The realpath check also prevents persistent parent links
        // from escaping the selected root.
        fileHandle = await open(absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        const realPath = await realpath(absolutePath);
        assertPathInside(root, realPath);
        const fileStat = await fileHandle.stat();
        if (!fileStat.isFile()) {
          skip("non_regular_file");
          continue;
        }
        if (fileStat.size > options.maxFileBytes) {
          skip("oversized_file");
          continue;
        }
        if (totalBytes + fileStat.size > options.maxTotalBytes) {
          totalBytesLimitReached = true;
          skip("total_bytes_limit");
          return;
        }
        const chunks: Buffer[] = [];
        let bytesReadTotal = 0;
        while (bytesReadTotal <= options.maxFileBytes) {
          const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, options.maxFileBytes + 1 - bytesReadTotal));
          const { bytesRead } = await fileHandle.read(chunk, 0, chunk.length, null);
          if (bytesRead === 0) break;
          bytesReadTotal += bytesRead;
          chunks.push(chunk.subarray(0, bytesRead));
        }
        if (bytesReadTotal > options.maxFileBytes) {
          skip("oversized_file");
          continue;
        }
        if (totalBytes + bytesReadTotal > options.maxTotalBytes) {
          totalBytesLimitReached = true;
          skip("total_bytes_limit");
          return;
        }
        // Count every inspected candidate byte, including files later rejected
        // as binary. Otherwise an attacker could bypass the aggregate I/O bound
        // with many NUL-containing files that use a supported source extension.
        totalBytes += bytesReadTotal;
        const content = Buffer.concat(chunks, bytesReadTotal).toString("utf8");
        if (content.includes("\u0000")) {
          skip("binary_file");
          continue;
        }
        files.push({
          absolutePath: realPath,
          relativePath: normalizeRelative(root, absolutePath),
          size: bytesReadTotal,
          content,
        });
      } catch (error) {
        const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
        if (code === "ELOOP") skip("symbolic_link");
        else if (error instanceof Error && error.message.startsWith("Path escapes scan root:")) skip("path_escape");
        else skip("unreadable_file");
      } finally {
        await fileHandle?.close().catch(() => undefined);
      }
    }
  }

  await walk(root);
  return { files, totalBytes, skippedFiles, skippedReasons };
}

export function findFile(files: ProjectFile[], name: string): ProjectFile | undefined {
  return files.find((file) => basename(file.relativePath) === name);
}

export function filesMatching(files: ProjectFile[], pattern: RegExp): ProjectFile[] {
  return files.filter((file) => pattern.test(file.relativePath));
}
