import { buildRelease } from "./release-lib.mjs";

let output = "release";
let allowDirty = false;
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--allow-dirty") allowDirty = true;
  else if (argument === "--output" && process.argv[index + 1]) output = process.argv[++index];
  else throw new Error(`Unknown release build argument: ${argument}`);
}

const result = await buildRelease(output, { allowDirty });
process.stdout.write(`Built and verified ${result.manifest.package.name}@${result.manifest.package.version} in ${result.outputDirectory}\n`);
