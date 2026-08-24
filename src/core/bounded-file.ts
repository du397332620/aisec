import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolve } from "node:path";

const READ_CHUNK_BYTES = 64 * 1024;

export async function readBoundedUtf8File(
  path: string,
  maxBytes: number,
  label: string,
): Promise<string> {
  const resolved = resolve(path);
  const file = await open(resolved, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const details = await file.stat();
    if (!details.isFile()) throw new Error(`${label} must be a regular file`);
    if (details.size > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);

    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maxBytes) {
      const remaining = maxBytes + 1 - total;
      const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, remaining));
      const { bytesRead } = await file.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      chunks.push(chunk.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);
    return Buffer.concat(chunks, total).toString("utf8");
  } finally {
    await file.close();
  }
}
