#!/usr/bin/env tsx
import * as path from "path";
import { fileURLToPath } from "url";
import { parseCliArgs, printCliHelp } from "../.manifold-api/t/lib/cli.js";
import { parseMountedKrl, printParseResult } from "../.manifold-api/t/lib/parse-krl.js";
import { setupManifoldBootstrap } from "../.manifold-api/t/lib/bootstrap.js";
import { runScenarioTests } from "./lib/run-tests.js";
import { setTestContext } from "../.manifold-api/t/lib/test-context.js";
import {
  clearTestContextFile,
  writeTestContextFile,
} from "../.manifold-api/t/lib/test-context-file.js";
import { setupSensorNetworkBootstrap } from "./lib/sensor.js";
import { setup } from "./setup.js";
import { teardown } from "./teardown.js";
import type { RuntimeState } from "../.manifold-api/t/lib/types.js";

const tDir = path.dirname(fileURLToPath(import.meta.url));
const defaultConfigPath = path.join(tDir, "config.json");

const args = process.argv.slice(2);
if (args.includes("-h") || args.includes("--help")) {
  printCliHelp();
  process.exit(0);
}

const opts = parseCliArgs(args);
const configPath = path.resolve(opts.configPath ?? defaultConfigPath);
const engineOpts = { manifoldApiPath: opts.manifoldApiPath };
let state: RuntimeState | null = null;
let passed = false;

try {
  if (!opts.skipParse) {
    const parseResult = parseMountedKrl(configPath, engineOpts);
    printParseResult(parseResult);
    if (!parseResult.ok) {
      process.exit(1);
    }
  }

  if (!opts.skipDocker) {
    state = await setup(configPath, engineOpts);
    setTestContext({ opts: { ...opts, configPath }, state });

    console.log("\nInstalling Manifold bootstrap…");
    const bootstrap = await setupManifoldBootstrap(state);
    setTestContext({ bootstrap });

    console.log("Installing sensor network bootstrap…");
    await setupSensorNetworkBootstrap(state, bootstrap);

    writeTestContextFile({ opts: { ...opts, configPath }, state, bootstrap });

    passed = runScenarioTests();
  } else {
    passed = true;
  }
} catch (err) {
  console.error("\nTest run failed:");
  console.error(err instanceof Error ? err.message : err);
  passed = false;
} finally {
  clearTestContextFile();
  if (!opts.skipDocker) {
    await teardown(state, { ...opts, configPath }, passed);
  }
}

// Node's test runner may set exitCode to the test count; override explicitly.
process.exitCode = passed ? 0 : 1;
process.exit(process.exitCode);
