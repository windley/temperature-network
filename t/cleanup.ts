#!/usr/bin/env tsx
import * as path from "path";
import { ensureManifoldApiLink, parsePrepareArgs } from "./lib/prepare-manifold-api.js";

const prepareOpts = parsePrepareArgs(process.argv.slice(2));
ensureManifoldApiLink(prepareOpts);

const { loadConfig } = await import("../.manifold-api/t/lib/config.js");
const { cleanupTestResources } = await import("../.manifold-api/t/lib/docker.js");
const { clearRuntime, readRuntime } = await import("../.manifold-api/t/lib/runtime.js");

function printHelp(): void {
  console.log(`Usage: tsx t/cleanup.ts [options]

Remove test containers and pico-engine home directories left behind by
test:keep or failed runs.

Options:
  --dry-run        List what would be removed without deleting
  --config <path>  Alternate t/config.json path
  -h, --help       Show this help
`);
}

const args = process.argv.slice(2);
if (args.includes("-h") || args.includes("--help")) {
  printHelp();
  process.exit(0);
}

let dryRun = false;
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--dry-run") {
    dryRun = true;
  } else if (arg.startsWith("-") && arg !== "--config" && arg !== "--manifold-api-path") {
    console.error(`Unknown flag: ${arg}`);
    process.exit(1);
  }
}

const resolvedConfigPath = path.resolve(prepareOpts.configPath);
const config = loadConfig(resolvedConfigPath);
const result = cleanupTestResources(resolvedConfigPath, { dryRun });

if (result.containers.length === 0 && result.picoHomes.length === 0) {
  console.log(`No test resources found for ${config.repoName}.`);
  process.exit(0);
}

const verb = dryRun ? "Would remove" : "Removed";
if (result.containers.length > 0) {
  console.log(`${verb} ${result.containers.length} container(s):`);
  for (const name of result.containers) {
    console.log(`  ${name}`);
  }
}
if (result.picoHomes.length > 0) {
  console.log(`${verb} ${result.picoHomes.length} pico home dir(s):`);
  for (const home of result.picoHomes) {
    console.log(`  ${home}`);
  }
}

if (!dryRun) {
  const runtime = readRuntime(resolvedConfigPath);
  if (
    runtime &&
    (result.containers.includes(runtime.containerName) ||
      result.picoHomes.includes(runtime.picoEngineHome))
  ) {
    clearRuntime(runtime);
    console.log("Cleared t/.runtime.json");
  }
}
