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

  if (opts.keep) {
    console.log("\nLeaving test container running (--keep):");
    console.log(formatRuntimeSummary(runtime));
    return;
  }

  if (!passed) {
    console.log("\nTest run failed. Tearing down container:");
    console.log(formatRuntimeSummary(runtime));
    if (!opts.retainLogs) {
      console.log(
        "\nTip: use --keep to leave the container up, or --retain-logs to keep pico home on disk."
      );
    }
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
