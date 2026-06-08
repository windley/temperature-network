import { startEngine } from "../.manifold-api/t/lib/docker.js";
import { formatRuntimeSummary } from "../.manifold-api/t/lib/runtime.js";
import type { RuntimeState } from "../.manifold-api/t/lib/types.js";

export async function setup(
  configPath: string,
  opts: { manifoldApiPath?: string } = {}
): Promise<RuntimeState> {
  const state = await startEngine(configPath, opts);
  console.log("Pico engine container started:");
  console.log(formatRuntimeSummary(state));
  return state;
}
