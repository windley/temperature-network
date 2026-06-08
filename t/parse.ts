#!/usr/bin/env tsx
import { ensureManifoldApiLink, parsePrepareArgs } from "./lib/prepare-manifold-api.js";

const prepareOpts = parsePrepareArgs(process.argv.slice(2));
ensureManifoldApiLink(prepareOpts);

const { parseMountedKrl, printParseResult } = await import(
  "../.manifold-api/t/lib/parse-krl.js"
);

const result = parseMountedKrl(prepareOpts.configPath, {
  manifoldApiPath: prepareOpts.manifoldApiPath,
});
printParseResult(result);
process.exit(result.ok ? 0 : 1);
