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
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;

    const append = (current: Buffer<ArrayBufferLike>, chunk: Buffer<ArrayBufferLike>): Buffer<ArrayBufferLike> => {
      if (current.length >= limit) {
        truncated = true;
        child.kill("SIGKILL");
        return current;
      }
      const remaining = limit - current.length;
      if (chunk.length > remaining) {
        truncated = true;
        child.kill("SIGKILL");
      }
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };
    child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });

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
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
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
