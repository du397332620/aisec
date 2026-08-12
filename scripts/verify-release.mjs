import { verifyRelease } from "./release-lib.mjs";

let directory = "release";
let allowDirty = false;
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--allow-dirty") allowDirty = true;
  else if (!argument.startsWith("--") && directory === "release") directory = argument;
  else throw new Error(`Unknown release verification argument: ${argument}`);
}

const manifest = await verifyRelease(directory, { allowDirty });
process.stdout.write(`Verified ${manifest.package.name}@${manifest.package.version} release artifacts.\n`);
