import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assertIncludes } from "../../.manifold-api/t/lib/assert.js";
import { waitForInstalledRids } from "../../.manifold-api/t/lib/bootstrap.js";
import { query } from "../../.manifold-api/t/lib/engine.js";
import {
  getCommunityThings,
  getThings,
} from "../../.manifold-api/t/lib/manifold.js";
import { getSensorTestContext } from "../lib/sensor-fixture.js";
import {
  createSensorThing,
  sensorThingRulesets,
} from "../lib/sensor.js";
import { getTestBootstrap, getTestState } from "../lib/test-context.js";

/**
 * Sensor types wired in io.picolabs.sensor.community `rids_to_install`.
 * Add entries here when new router types are registered in that map.
 *
 * Note: io.picolabs.ldds20.router exists in this repo but is not yet in
 * sensor.community rids_to_install — add a case here once it is.
 */
const SENSOR_INITIATION_CASES = [
  { type: "lht65", name: "Test LHT65" },
  { type: "lse01", name: "Test LSE01" },
  { type: "lsn50", name: "Test LSN50" },
] as const;

describe("sensor initiation", () => {
  for (const { type, name } of SENSOR_INITIATION_CASES) {
    it(`creates a ${type} sensor thing with Manifold and sensor-network rulesets`, async () => {
      const state = getTestState();
      const bootstrap = getTestBootstrap();
      const { communityUiEci, communityQueryEci, manifoldAppEci } =
        getSensorTestContext();

      const required = sensorThingRulesets(type);
      const { entry, uiEci } = await createSensorThing(
        state,
        bootstrap,
        communityUiEci,
        communityQueryEci,
        manifoldAppEci,
        name,
        type
      );

      const picoName = await query<string>(
        state,
        uiEci,
        "io.picolabs.pico-engine-ui",
        "name"
      );
      assert.equal(picoName, name);

      const rids = await waitForInstalledRids(
        state,
        uiEci,
        required,
        `Sensor thing (${type})`
      );
      assertIncludes(rids, [...required], `Sensor thing (${type})`);

      assert.equal(entry.Tx_role, "manifold_thing");
      assert.ok(entry.Id && entry.Tx, "Manifold→thing subscription missing Id or Tx channel");

      const communityThings = await getCommunityThings(state, communityQueryEci);
      const member = communityThings.find(t => t.name === name);
      assert.ok(member, `community missing thing "${name}"`);
      assert.equal(member.Tx_role, "thing");

      const things = await getThings(state, manifoldAppEci);
      assert.ok(things[entry.picoID], "thing missing from Manifold getThings");
    });
  }
});
