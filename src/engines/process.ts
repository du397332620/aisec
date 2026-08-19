import { spawn } from "node:child_process";

const SENSITIVE_ENVIRONMENT_NAME = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

export function sanitizedProcessEnv(environment: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(environment).filter(([name]) => !SENSITIVE_ENVIRONMENT_NAME.test(name)));
}

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

export interface ProcessBufferResult extends Omit<ProcessResult, "stdout" | "stderr"> {
  stdout: Buffer;
  stderr: Buffer;
}

export async function runProcessBuffer(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs: number; maxOutputBytes?: number; env?: NodeJS.ProcessEnv },
): Promise<ProcessBufferResult> {
  const started = Date.now();
  const limit = options.maxOutputBytes ?? 20 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: options.env ?? sanitizedProcessEnv(),
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
        stdout: Buffer.concat(stdoutChunks, stdoutBytes),
        stderr: Buffer.concat(stderrChunks, stderrBytes),
        timedOut,
        truncated,
        durationMs: Date.now() - started,
      });
    });
  });
}

export async function runProcess(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs: number; maxOutputBytes?: number; env?: NodeJS.ProcessEnv },
): Promise<ProcessResult> {
  const result = await runProcessBuffer(command, args, options);
  return {
    ...result,
    stdout: result.stdout.toString("utf8"),
    stderr: result.stderr.toString("utf8"),
  };
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
