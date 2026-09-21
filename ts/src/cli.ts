// Standalone verifier CLI -- the TypeScript counterpart of the Python/C#/Java CLIs.
//
//     node --experimental-strip-types src/cli.ts <response.json>

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { QueryResponse } from "./models.ts";
import { verifyResponse } from "./verification.ts";

/** Run the verifier CLI, returning the process exit code. */
export function runCli(argv: string[]): number {
  if (argv.length !== 1) {
    console.log("usage: ledgerrag-verify <response.json>");
    return 2;
  }
  let resp: QueryResponse;
  try {
    resp = JSON.parse(readFileSync(argv[0], "utf8")) as QueryResponse;
  } catch (err) {
    console.error(String(err));
    return 2;
  }
  let result;
  try {
    result = verifyResponse(resp);
  } catch (err) {
    console.error(String(err));
    return 2;
  }
  console.log(result.verified ? "\u2705 VERIFIED (TypeScript)" : "\u274c TAMPERED / INVALID (TypeScript)");
  console.log(JSON.stringify(result, null, 2));
  return result.verified ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(runCli(process.argv.slice(2)));
}
