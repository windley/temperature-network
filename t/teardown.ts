import { teardownRuntime } from "../.manifold-api/t/lib/docker.js";
import {
  clearRuntime,
  formatRuntimeSummary,
  readRuntime,
} from "../.manifold-api/t/lib/runtime.js";
import type { CliOptions, RuntimeState } from "../.manifold-api/t/lib/types.js";

export async function teardown(
  state: RuntimeState | null,
  opts: Pick<CliOptions, "keep" | "retainLogs"> & { configPath: string },
  passed: boolean
): Promise<void> {
  const runtime = state ?? readRuntime(opts.configPath);
  if (!runtime) {
    return;
  }

  if (opts.keep || !passed) {
    console.log("\nLeaving test container running for inspection:");
    console.log(formatRuntimeSummary(runtime));
    if (!passed) {
      console.log("\nFix the failure, then stop manually:");
      console.log(`  docker rm -f ${runtime.containerName}`);
      console.log(`  rm -rf ${runtime.picoEngineHome}`);
    }
    return;
  }

  await teardownRuntime(runtime, { retainLogs: opts.retainLogs });
  clearRuntime(runtime);
  console.log("\nTest container removed.");
  if (opts.retainLogs) {
    console.log(`Pico engine home retained at: ${runtime.picoEngineHome}`);
  } else {
    console.log("Pico engine home deleted.");
  }
}
