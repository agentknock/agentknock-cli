#!/usr/bin/env node

import { accessSync, constants } from "node:fs";
import { fileURLToPath } from "node:url";
import process from "node:process";

function fail(message) {
  console.error(`agentknock: ${message}`);
  process.exit(1);
}

if (typeof process.execve !== "function") {
  fail(
    `Process replacement is unavailable in Node.js ${process.version}. ` +
      "Upgrade to a supported Node.js release.",
  );
}

const target = (() => {
  switch (`${process.platform}/${process.arch}`) {
    case "linux/x64":
      return "x86_64-unknown-linux-musl";
    case "linux/arm64":
      return "aarch64-unknown-linux-musl";
    case "darwin/arm64":
      return "aarch64-apple-darwin";
    default:
      fail(`This package does not support ${process.platform}/${process.arch}.`);
  }
})();

const binaryUrl = new URL(`bin/agentknock-${target}`, import.meta.url);
const binaryPath = fileURLToPath(binaryUrl);

try {
  accessSync(binaryUrl, constants.X_OK);
} catch {
  fail("The native executable is missing. Reinstall the package.");
}

try {
  process.execve(
    binaryPath,
    [binaryPath, ...process.argv.slice(2)],
    process.env,
  );
} catch (error) {
  fail(`Could not start the native executable: ${error.message}`);
}
