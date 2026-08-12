import { spawn } from "node:child_process";

export interface ProcessResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
}

export async function runProcess(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs: number; maxOutputBytes?: number; env?: NodeJS.ProcessEnv },
): Promise<ProcessResult> {
  const started = Date.now();
  const limit = options.maxOutputBytes ?? 20 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: options.env ?? process.env,
    });
    const stdoutChunks: Buffer<ArrayBufferLike>[] = [];
    const stderrChunks: Buffer<ArrayBufferLike>[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let capturedBytes = 0;
    let truncated = false;
    let timedOut = false;

    const append = (destination: Buffer<ArrayBufferLike>[], chunk: Buffer<ArrayBufferLike>, stream: "stdout" | "stderr"): void => {
      const remaining = limit - capturedBytes;
      if (remaining <= 0) {
        truncated = true;
        child.kill("SIGKILL");
        return;
      }
      if (chunk.length > remaining) {
        truncated = true;
        child.kill("SIGKILL");
      }
      const captured = chunk.subarray(0, remaining);
      destination.push(captured);
      capturedBytes += captured.length;
      if (stream === "stdout") stdoutBytes += captured.length;
      else stderrBytes += captured.length;
    };
    child.stdout.on("data", (chunk: Buffer) => { append(stdoutChunks, chunk, "stdout"); });
    child.stderr.on("data", (chunk: Buffer) => { append(stderrChunks, chunk, "stderr"); });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeoutMs);
    timer.unref();

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      resolve({
        command,
        args,
        exitCode,
        stdout: Buffer.concat(stdoutChunks, stdoutBytes).toString("utf8"),
        stderr: Buffer.concat(stderrChunks, stderrBytes).toString("utf8"),
        timedOut,
        truncated,
        durationMs: Date.now() - started,
      });
    });
  });
}

export async function commandVersion(command: string, args: string[] = ["--version"]): Promise<string | undefined> {
  try {
    const result = await runProcess(command, args, { timeoutMs: 5_000, maxOutputBytes: 32_768 });
    if (result.exitCode !== 0 || result.timedOut || result.truncated) return undefined;
    const value = `${result.stdout}\n${result.stderr}`.trim().split("\n")[0]?.trim();
    return value || undefined;
  } catch {
    return undefined;
  }
}
