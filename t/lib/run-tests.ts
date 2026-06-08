import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Run scenarios in a child `node --test` process.
 *
 * The parent (t/run.ts) owns Docker/bootstrap; the child only executes tests.
 * In-process programmatic run() can hang before teardown (Node 18) or run tests
 * twice with conflicting reporters (Node 22), which leaks containers.
 *
 * Use one entry module so scenarios share in-process fixtures (sensor-community
 * → sensor-initiation). Passing multiple files to node --test isolates modules.
 */
export function runScenarioTests(): boolean {
  const scenariosDir = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "../scenarios"
  );
  const entry = path.join(scenariosDir, "index.ts");

  const tsxImport = path.join(
    process.cwd(),
    "node_modules/tsx/dist/loader.mjs"
  );

  const result = spawnSync(
    process.execPath,
    [
      "--import",
      tsxImport,
      "--test",
      "--test-concurrency=1",
      entry,
    ],
    {
      stdio: "inherit",
      env: { ...process.env, MANIFOLD_TEST_CHILD: "1" },
    }
  );

  if (result.error) {
    throw result.error;
  }

  return result.status === 0;
}
