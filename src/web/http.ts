import { lookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";

export interface BoundedHttpRequest {
  url: string;
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  local: boolean;
  maxResponseBytes?: number;
  captureBody?: boolean;
}

export interface BoundedHttpResponse {
  url: string;
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

const unsafeAddresses = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
] as Array<[string, number]>) unsafeAddresses.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["fc00::", 7], ["fe80::", 10],
  ["fec0::", 10], ["ff00::", 8], ["2001:db8::", 32],
] as Array<[string, number]>) unsafeAddresses.addSubnet(network, prefix, "ipv6");

const localAddresses = new BlockList();
for (const [network, prefix] of [
  ["10.0.0.0", 8], ["127.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16],
] as Array<[string, number]>) localAddresses.addSubnet(network, prefix, "ipv4");
localAddresses.addAddress("::1", "ipv6");

function hostWithoutBrackets(url: URL): string { return url.hostname.replace(/^\[|\]$/g, ""); }

async function pinnedAddress(url: URL, local: boolean): Promise<LookupAddress> {
  const hostname = hostWithoutBrackets(url);
  const literalFamily = isIP(hostname);
  const addresses = literalFamily
    ? [{ address: hostname, family: literalFamily as 4 | 6 }]
    : await new Promise<LookupAddress[]>((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error(`Authorized target DNS lookup timed out: ${hostname}`)), 5_000);
      deadline.unref();
      lookup(hostname, { all: true, verbatim: true }).then(
        (result) => { clearTimeout(deadline); resolve(result); },
        (error: unknown) => { clearTimeout(deadline); reject(error); },
      );
    });
  if (addresses.length === 0) throw new Error(`Authorized target did not resolve: ${hostname}`);
  if (local) {
    const nonLocal = addresses.find((item) => !localAddresses.check(item.address, item.family === 6 ? "ipv6" : "ipv4"));
    if (nonLocal) throw new Error(`Local target resolved outside loopback or RFC1918 space and was refused: ${nonLocal.address}`);
  } else {
    const unsafe = addresses.find((item) => unsafeAddresses.check(item.address, item.family === 6 ? "ipv6" : "ipv4"));
    if (unsafe) throw new Error(`Authorized target resolved to a non-public address and was refused: ${unsafe.address}`);
  }
  return addresses[0]!;
}

export async function boundedHttpRequest(input: BoundedHttpRequest): Promise<BoundedHttpResponse> {
  const url = new URL(input.url);
  const address = await pinnedAddress(url, input.local);
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
  const maxResponseBytes = input.maxResponseBytes ?? 512 * 1024;
  const bodyBytes = input.body === undefined ? 0 : Buffer.byteLength(input.body);
  if (bodyBytes > 64 * 1024) throw new Error("Authorized request body exceeds the 64 KiB safety limit");
  return new Promise((resolve, reject) => {
    let settled = false;
    let request: ReturnType<typeof httpRequest>;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const complete = <T>(callback: (value: T) => void, value: T): void => {
      if (settled) return;
      settled = true;
      if (deadline) clearTimeout(deadline);
      callback(value);
    };
    request = transport(url, {
      method: input.method,
      agent: false,
      maxHeaderSize: 64 * 1024,
      headers: {
        "user-agent": "AIsec/0.1 authorized-verifier",
        accept: "application/json,text/html;q=0.5,*/*;q=0.1",
        "accept-encoding": "identity",
        ...(input.body === undefined ? {} : { "content-length": String(bodyBytes) }),
        ...input.headers,
      },
      lookup: (_hostname, _options, callback) => callback(null, address.address, address.family),
    }, (response) => {
      if (input.captureBody === false) {
        response.destroy();
        complete(resolve, { url: input.url, status: response.statusCode ?? 0, headers: response.headers, body: "" });
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", (chunk: Buffer | string) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += bytes.length;
        if (total > maxResponseBytes) {
          response.destroy(new Error(`Authorized response exceeded the ${maxResponseBytes}-byte safety limit`));
          complete(reject, new Error(`Authorized response exceeded the ${maxResponseBytes}-byte safety limit`));
          return;
        }
        chunks.push(bytes);
      });
      response.once("end", () => {
        if (settled) return;
        complete(resolve, {
          url: input.url,
          status: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
      response.once("error", (error) => {
        if (settled) return;
        complete(reject, error);
      });
    });
    deadline = setTimeout(() => {
      if (settled) return;
      request.destroy(new Error("Authorized web request exceeded the 20-second absolute deadline"));
    }, 20_000);
    deadline.unref();
    request.setTimeout(15_000, () => request.destroy(new Error("Authorized web request timed out")));
    request.once("error", (error) => {
      if (settled) return;
      complete(reject, error);
    });
    if (input.body !== undefined) request.write(input.body);
    request.end();
  });
}
