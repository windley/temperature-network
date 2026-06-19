import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getPdsChannelEci, pdsProfile } from "../../.manifold-api/t/lib/pds.js";
import { assertIncludes } from "../../.manifold-api/t/lib/assert.js";
import { waitForInstalledRids } from "../../.manifold-api/t/lib/bootstrap.js";
import { query } from "../../.manifold-api/t/lib/engine.js";
import { getCommunities } from "../../.manifold-api/t/lib/manifold.js";
import {
  createSensorCommunity,
  SENSOR_COMMUNITY_RULESETS,
} from "../lib/sensor.js";
import { setSensorTestContext } from "../lib/sensor-fixture.js";
import { getTestBootstrap, getTestState } from "../lib/test-context.js";

const COMMUNITY_NAME = "Test Sensors";
const COMMUNITY_DESCRIPTION = "Sensor network integration test community";

describe("sensor community", () => {
  it("creates a sensor community with sensor.community and Manifold subscription", async () => {
    const state = getTestState();
    const bootstrap = getTestBootstrap();

    const { entry, uiEci, appEci, communityQueryEci } = await createSensorCommunity(
      state,
      bootstrap,
      COMMUNITY_NAME,
      COMMUNITY_DESCRIPTION
    );

    setSensorTestContext({
      communityName: COMMUNITY_NAME,
      communityUiEci: uiEci,
      communityQueryEci,
      manifoldAppEci: appEci,
    });

    assert.equal(entry.name, COMMUNITY_NAME);
    assert.ok(entry.picoID, "sensor community entry missing picoID");

    const name = await query<string>(
      state,
      uiEci,
      "io.picolabs.pico-engine-ui",
      "name"
    );
    assert.equal(name, COMMUNITY_NAME);

    const rids = await waitForInstalledRids(
      state,
      uiEci,
      SENSOR_COMMUNITY_RULESETS,
      "Sensor community pico"
    );
    assertIncludes(rids, [...SENSOR_COMMUNITY_RULESETS], "Sensor community pico");

    const communities = await getCommunities(state, appEci);
    const manifoldEntry = Object.values(communities).find(c => c.name === COMMUNITY_NAME);
    assert.ok(manifoldEntry, `Manifold getCommunities missing "${COMMUNITY_NAME}"`);
    assert.equal(manifoldEntry.picoID, entry.picoID);

    const pdsEci = await getPdsChannelEci(state, uiEci);
    const profileName = await pdsProfile(state, pdsEci, "name");
    assert.equal(profileName.status, "success");
    assert.equal(profileName.profile, COMMUNITY_NAME);
  });
});
