import { toFileRulesetUrl } from "../../.manifold-api/t/lib/config.js";
import { assertTruthy } from "../../.manifold-api/t/lib/assert.js";
import {
  findChildUiByName,
  waitForInstalledRids,
  type ManifoldBootstrapContext,
} from "../../.manifold-api/t/lib/bootstrap.js";
import { query, signalWait, waitFor } from "../../.manifold-api/t/lib/engine.js";
import {
  getCommunities,
  getCommunityThings,
  getManifoldAppEci,
  getThings,
  type ManifoldThingEntry,
} from "../../.manifold-api/t/lib/manifold.js";
import { THING_RULESETS } from "../../.manifold-api/t/lib/expected-rulesets.js";
import type { RuntimeState } from "../../.manifold-api/t/lib/types.js";

const SENSOR_NETWORK_BOOTSTRAP_RS = "io.picolabs.sensor.network_bootstrap.krl";
const SENSOR_NETWORK_BOOTSTRAP_RID = "io.picolabs.sensor.network_bootstrap";
const SENSOR_COMMUNITY_RID = "io.picolabs.sensor.community";

export const SENSOR_COMMUNITY_RULESETS = [
  "io.picolabs.community",
  SENSOR_COMMUNITY_RID,
] as const;

/** Rulesets from sensor.community `rids_to_install.all` — installed on every sensor thing. */
export const SENSOR_ALL_THING_RULESETS = [
  "io.picolabs.sensor.thresholds",
  "io.picolabs.iotplotter",
  "io.picolabs.dragino",
] as const;

/** Per-type router rulesets from sensor.community `rids_to_install`. */
export const SENSOR_TYPE_RULESETS: Record<string, readonly string[]> = {
  lht65: ["io.picolabs.lht65.router"],
  lse01: ["io.picolabs.lse01.router"],
  lsn50: ["io.picolabs.lsn50.router"],
  wl03a_lb: ["io.picolabs.wl03a_lb.router"],
};

export function sensorThingRulesets(sensorType: string): readonly string[] {
  const typeRids = SENSOR_TYPE_RULESETS[sensorType] ?? [];
  return [...THING_RULESETS, ...SENSOR_ALL_THING_RULESETS, ...typeRids];
}

interface PicoChannel {
  id: string;
  name?: string;
  tags?: string[];
}

interface PicoDetails {
  channels: PicoChannel[];
}

export function sensorNetworkMountPath(state: RuntimeState): string {
  const mount = state.mounts.find(m => m.name === "sensor-network");
  assertTruthy(mount, "sensor-network mount not configured in t/config.json");
  return mount.containerPath;
}

async function flushSensorRuleset(
  state: RuntimeState,
  rulesetFile: string
): Promise<void> {
  const url = toFileRulesetUrl(sensorNetworkMountPath(state), rulesetFile);
  const resp = await fetch(
    `${state.baseUrl}/api/flush?url=${encodeURIComponent(url)}`
  );
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Flush ${rulesetFile} failed (${resp.status}): ${body}`);
  }
}

async function installSensorRuleset(
  state: RuntimeState,
  uiEci: string,
  rulesetFile: string,
  config: Record<string, unknown> = {}
): Promise<void> {
  const url = toFileRulesetUrl(sensorNetworkMountPath(state), rulesetFile);
  const resp = await fetch(`${state.baseUrl}/c/${uiEci}/event-wait/engine_ui/install`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, config }),
  });
  const body = await resp.text();
  if (!resp.ok) {
    throw new Error(`Install ${rulesetFile} failed (${resp.status}): ${body}`);
  }
}

/** Install sensor.network_bootstrap on the Manifold pico after Manifold bootstrap. */
export async function setupSensorNetworkBootstrap(
  state: RuntimeState,
  bootstrap: ManifoldBootstrapContext
): Promise<void> {
  const { manifoldUiEci } = bootstrap;
  await flushSensorRuleset(state, SENSOR_NETWORK_BOOTSTRAP_RS);
  await installSensorRuleset(state, manifoldUiEci, SENSOR_NETWORK_BOOTSTRAP_RS);
  await waitForInstalledRids(
    state,
    manifoldUiEci,
    [SENSOR_NETWORK_BOOTSTRAP_RID],
    "Manifold pico sensor bootstrap"
  );
}

export interface SensorCommunityEntry {
  name: string;
  description?: string;
  picoID: string;
  rcn?: string;
  created?: number;
}

export async function getSensorCommunities(
  state: RuntimeState,
  manifoldAppEci: string
): Promise<SensorCommunityEntry[]> {
  const result = await query<SensorCommunityEntry[] | Record<string, SensorCommunityEntry>>(
    state,
    manifoldAppEci,
    SENSOR_NETWORK_BOOTSTRAP_RID,
    "getSensorCommunities"
  );
  return Array.isArray(result) ? result : Object.values(result ?? {});
}

export async function getCommunitySensorEci(
  state: RuntimeState,
  communityUiEci: string
): Promise<string> {
  const pico = await query<PicoDetails>(
    state,
    communityUiEci,
    "io.picolabs.pico-engine-ui",
    "pico"
  );
  const channel = pico.channels.find(c => c.tags?.includes("sensor"));
  if (!channel) {
    throw new Error(`sensor channel not found on community ${communityUiEci}`);
  }
  return channel.id;
}

async function waitForManifoldThingEntry(
  state: RuntimeState,
  manifoldAppEci: string,
  name: string
): Promise<ManifoldThingEntry> {
  return waitFor(
    async () => {
      const things = await getThings(state, manifoldAppEci);
      const entry = Object.values(things).find(t => t.name === name);
      if (entry?.picoID && entry.subID && entry.Tx && entry.Id) {
        return entry;
      }
      return null;
    },
    { timeoutMs: 120_000, intervalMs: 500, label: `thing "${name}" in Manifold` }
  );
}

export async function waitForCommunityHasThing(
  state: RuntimeState,
  communityQueryEci: string,
  thingName: string
): Promise<void> {
  await waitFor(
    async () => {
      const things = await getCommunityThings(state, communityQueryEci);
      if (things.some(t => t.name === thingName)) {
        return true;
      }
      return null;
    },
    {
      timeoutMs: 120_000,
      intervalMs: 500,
      label: `thing "${thingName}" in community`,
    }
  );
}

export async function createSensorCommunity(
  state: RuntimeState,
  bootstrap: ManifoldBootstrapContext,
  name: string,
  description?: string
): Promise<{
  entry: SensorCommunityEntry;
  uiEci: string;
  appEci: string;
  communityQueryEci: string;
}> {
  const { manifoldUiEci } = bootstrap;
  const appEci = await getManifoldAppEci(state, manifoldUiEci);
  await signalWait(state, appEci, "sensor", "create_community", {
    name,
    description,
  });

  const entry = await waitFor(
    async () => {
      const communities = await getSensorCommunities(state, appEci);
      const match = communities.find(c => c.name === name);
      if (match?.picoID) {
        return match;
      }
      return null;
    },
    { timeoutMs: 120_000, intervalMs: 500, label: `sensor community "${name}"` }
  );

  const uiEci = await waitFor(
    async () => findChildUiByName(state, manifoldUiEci, name),
    { timeoutMs: 120_000, intervalMs: 500, label: `sensor community child UI "${name}"` }
  );

  const manifoldEntry = await waitFor(
    async () => {
      const communities = await getCommunities(state, appEci);
      const match = Object.values(communities).find(c => c.name === name);
      if (match?.Tx && match.picoID) {
        return match;
      }
      return null;
    },
    { timeoutMs: 120_000, intervalMs: 500, label: `Manifold community "${name}"` }
  );

  return { entry, uiEci, appEci, communityQueryEci: manifoldEntry.Tx };
}

/** Create a sensor thing via `sensor initiation` on the community's sensor channel. */
export async function createSensorThing(
  state: RuntimeState,
  bootstrap: ManifoldBootstrapContext,
  communityUiEci: string,
  communityQueryEci: string,
  appEci: string,
  name: string,
  sensorType: string
): Promise<{ entry: ManifoldThingEntry; uiEci: string; thingQueryEci: string }> {
  const sensorEci = await getCommunitySensorEci(state, communityUiEci);
  await signalWait(state, sensorEci, "sensor", "initiation", {
    name,
    type: sensorType,
  });

  const entry = await waitForManifoldThingEntry(state, appEci, name);
  await waitForCommunityHasThing(state, communityQueryEci, name);

  const uiEci = await waitFor(
    async () => findChildUiByName(state, bootstrap.manifoldUiEci, name),
    { timeoutMs: 120_000, intervalMs: 500, label: `sensor thing child UI "${name}"` }
  );

  const required = sensorThingRulesets(sensorType);
  await waitForInstalledRids(state, uiEci, required, `Sensor thing (${sensorType})`);

  return { entry, uiEci, thingQueryEci: entry.Tx };
}
