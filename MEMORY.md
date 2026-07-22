# MEMORY: sensor-network

Working context for this repo across sessions. For Manifold migration history and
manifold-api harness details, see [`../manifold-api/MEMORY.md`](../manifold-api/MEMORY.md).

## WHERE WE ARE (2026-06-09)

### Summary

Integration tests live in **`sensor-network/t/`**. The harness reuses manifold-api's
Docker/bootstrap stack via `dependsOn`, `manifoldApiPath`, and a `.manifold-api` symlink for
TypeScript imports — it does **not** duplicate the full test infrastructure.

**Automated regression (today):** **5 tests** pass in ~10s when Docker is running:
health, sensor community creation (incl. PDS profile name), and sensor initiation for **lht65**,
**lse01**, and **lsn50** (incl. PDS on thing picos).

**Not yet automated:** readings/threshold path, notification delivery verification.

**GitHub:** `windley/sensor-network` (renamed from `temperature-network`, 2026-06-09).
Pushed; local remote `origin` → `https://github.com/windley/sensor-network.git`.

**Recommended runtime:** Node **22 LTS** (requires 18+).

### Verified working (automated, 2026-06-09)

| Scenario | What it proves |
|----------|----------------|
| `health` | Pico engine reachable over HTTP |
| `sensor community` | `sensor create_community` → Manifold child with PDS + `io.picolabs.community` + `io.picolabs.sensor.community`; PDS profile name; `getSensorCommunities` enriches from PDS |
| `sensor initiation` (×3) | `sensor initiation` per type → thing with PDS + Manifold thing RSs + sensor RSs + type router; PDS profile name matches thing name; community `things()` via manifold-api PDS-aware community RS |

### Verified working (manual, pre-harness)

See manifold-api MEMORY.md — readings path and threshold → `manifold add_notification` were
exercised manually before this harness existed.

### Recent commits (2026-06-09)

| Commit | Summary |
|--------|---------|
| `48c3fcd` | Integration harness, `sensor.network_bootstrap`, Manifold delegation refactor, removed duplicate prowl/twilio/wovyn RSs |
| `c4c6527` | Architecture diagram + expanded root README |

---

## Integration test harness

**Location:** `sensor-network/t/` (see `t/README.md`)

**Repo layout:** `manifold-api` can live anywhere on disk. Set `manifoldApiPath` in
`t/config.json` (default `../manifold-api`), or pass `--manifold-api-path` / `MANIFOLD_API_PATH`.
The harness creates a `.manifold-api` symlink for TypeScript imports and mounts the checkout
into Docker via `dependsOn`.

```
picolabs/   (typical layout — not required)
  manifold-api/
  sensor-network/
    t/config.json   → manifoldApiPath: "../manifold-api"
    .manifold-api   → symlink (gitignored, created by t/run.ts)
```

### What we built

| Piece | Purpose |
|-------|---------|
| `t/config.json` | Own mount at `/var/sensor-network`; `manifoldApiPath` + `dependsOn` for manifold-api |
| `t/run.ts` | Symlink prep → parse → Docker → Manifold bootstrap → sensor bootstrap → scenarios → teardown |
| `t/run-main.ts` | Orchestrator; writes `t/.test-context.json` for scenario subprocess |
| `t/lib/prepare-manifold-api.ts` | Resolves `manifoldApiPath`; creates `.manifold-api` symlink |
| `t/lib/sensor.ts` | `setupSensorNetworkBootstrap()`, `createSensorCommunity()`, `createSensorThing()` |
| `t/lib/run-tests.ts` | Spawns child `node --test` on `t/scenarios/index.ts` only |
| `t/lib/sensor-fixture.ts` | In-process fixture: community scenario → initiation scenarios |
| `t/lib/test-context.ts` | Re-exports manifold-api test fixtures |
| `t/scenarios/index.ts` | Single entry: community → initiation → health (order matters) |
| `t/disable-auto-test.mjs` | Prevents tsx from auto-running tests before bootstrap |
| `package.json` | `npm test`, `test:parse`, `test:keep`, `test:cleanup` |

### Test run flow

```
npm test
  → ensureManifoldApiLink()       ← .manifold-api symlink
  → parse (sensor-network + manifold-api KRL via dependsOn)
  → one Docker container, both mounts
  → setupManifoldBootstrap()      ← from .manifold-api/t/lib
  → setupSensorNetworkBootstrap() ← installs io.picolabs.sensor.network_bootstrap
  → write t/.test-context.json
  → child: node --test t/scenarios/index.ts
  → teardown (leave container on failure)
```

Manifold-api's bootstrap and thing/community scenarios are **not** re-run here.

### Commands

```bash
cd sensor-network && npm install
npm test                    # full run (~10s, 5 tests)
npm run test:parse          # krl-compiler on both repos' mounted KRL
npm run test:keep           # leave container up after run
npm run test:cleanup        # remove leftover containers + /tmp pico homes
npm test -- --skip-parse    # Docker + scenarios only
```

Runtime state: `t/.runtime.json` (gitignored). Test context file lives in manifold-api's
`t/.test-context.json` (resolved via symlinked module path).

---

## Reuse pattern (dependsOn + symlink)

**`dependsOn` in config** mounts manifold-api into the same container and includes its KRL in
the parse gate.

**TypeScript reuse:** import from `.manifold-api/t/lib/...` (symlink to local checkout).
Import depth matters — paths are relative to each file's location under `t/`:

| From | Import prefix |
|------|---------------|
| `t/run-main.ts`, `t/setup.ts`, `t/teardown.ts` | `../.manifold-api/t/lib/...` |
| `t/lib/*.ts`, `t/scenarios/*.ts` | `../../.manifold-api/t/lib/...` |

**manifold-api harness change for cross-repo support:** `manifoldApiPath` on `TestConfig`,
`--manifold-api-path` CLI flag, `MANIFOLD_API_PATH` env, `resolveDependencyHostPath()`.

---

## Gotchas discovered while building tests

### 1. Manifold app channel for sensor domain

`sensor create_community` and `getSensorCommunities` must use the **Manifold app channel**
(`getManifoldAppEci`), not the Manifold UI ECI. The UI channel's event policy returns
`Not allowed by channel policy` for `sensor` domain events.

Implemented in `t/lib/sensor.ts` — all sensor signals and network_bootstrap queries go
through app ECI.

### 2. Subprocess test runner (`run-tests.ts`)

Scenarios run in a child `node --test` process (same pattern as manifold-api). The parent
owns Docker/bootstrap; the child reads fixtures from `.test-context.json`.

Use a **single entry module** (`t/scenarios/index.ts`) so scenarios share in-process state
(community → initiation fixture). Passing multiple files to `node --test` isolates modules
and breaks that chain.

**Do not** use in-process programmatic `run()` — Node 22 runs tests twice with conflicting
reporters (wrong pass count); Node 18 hangs before teardown and leaks containers.

### 3. `.manifold-api` import paths

One extra `../` resolves to `picolabs/.manifold-api` instead of `sensor-network/.manifold-api`.
Symptom: `ERR_MODULE_NOT_FOUND` for `t/lib/cli.js`.

### 4. Scenario files named `*.scenario.ts`

Not `*.test.ts` — avoids tsx auto-discovery before bootstrap completes.

### 5. Import order in `scenarios/index.ts`

Community before initiation (initiation reads fixture set by community):

```typescript
import "./sensor-community.scenario.js";
import "./sensor-initiation.scenario.js";
import "./health.scenario.js";
```

### 6. `getSensorCommunities` return shape

The KRL function returns a map's `.values()`. The HTTP query may come back as an object, not
an array. `getSensorCommunities()` normalizes with `Object.values()`.

### 7. Parse exclusions / removed rulesets

Removed from repo (now in manifold-api): `io.picolabs.prowl.krl`, `io.picolabs.twilio.sms.krl`.
Removed legacy: `io.picolabs.wovyn.*`.

Parse exclusions in `t/config.json`: `OLD/**`, `dotfile_for_temp_network/**`; manifold-api
`dependsOn` excludes `OLD/**`, `fix/**`, alexa/google assistant.

---

## KRL architecture (this repo on Manifold)

| Ruleset | Installed on | Role |
|---------|--------------|------|
| `io.picolabs.sensor.network_bootstrap` | Manifold pico | `sensor create_community` → delegate to `manifold new_community`; install `sensor.community`; provision notifications |
| `io.picolabs.sensor.community` | Community pico | `sensor initiation` → delegate `manifold create_thing`; finish via callback; install routers |
| `io.picolabs.*.router` | Thing picos | Decode LoRaWAN payloads; `thing community_notify` for readings |
| `io.picolabs.sensor.thresholds` | Thing picos | Threshold violations → community via `community_notify` |

Notifications: community `catch_threshold_violation` → `manifold add_notification` (subject =
community picoId). Do not call Twilio/Prowl directly.

Root README documents Manifold services used and bootstrap flow (`sensor_network.png` diagram).

---

## Home Assistant companion (2026-07-21)

**Domain:** `pico_mesh_sensor_network` (display name **Manifold Sensor Network**)  
**Location:** `custom_components/pico_mesh_sensor_network/` in this repo  
**Depends on:** [`manifold-home-assistant`](../manifold-home-assistant) hub (`pico_mesh`)

Reference implementation of the **Manifold companion pattern** — co-publish KRL + HA integration
from one repo; see [`../manifold-home-assistant/MEMORY.md`](../manifold-home-assistant/MEMORY.md).

### Layout

```
sensor-network/
  io.picolabs.*.krl
  custom_components/pico_mesh_sensor_network/
  hacs.json
```

### Behavior

- Config flow links to one Manifold hub config entry (`unique_id = hub_entry_id` → **one companion
  entry per hub**; multiple hubs on one HA each get their own entry).
- `SensorNetworkCoordinator` refreshes when the hub coordinator polls.
- Probes `wrangler:installedRIDs` on each thing Tx; for LHT65 installs router queries.
- Sensor entities attach to existing Manifold **thing** devices (same device registry identifiers).

### LHT65 entities (verified working)

| Entity | Query | Unit |
|--------|-------|------|
| Temperature | `lastInternalTemp` | °F |
| Humidity | `lastHumidity` | % |
| Probe temperature | `lastProbeTemp` | °F (unavailable if no probe) |
| Last reading | `lastHeartbeat` → `reported_at` | timestamp |

Router rulesets do **not** use Manifold discovery; companion uses ruleset probe (same approach as
pre-refactor hub code).

### Install

1. Manifold hub (`pico_mesh`) configured in HA.
2. Add integration **Manifold Sensor Network** → select hub.
3. Docker: mount companion in compose (see sensor-network README).

### Still open (HA)

| Item | Notes |
|------|-------|
| LSE01 / LSN50 / WL03A drivers | Add under `drivers/` |
| Subentries / auto-provision | UX revisit — see hub MEMORY |
| HA in CI | Not in harness yet |

---

## Still open / next steps (KRL / tests)

| Item | Notes |
|------|-------|
| **Readings scenario** | Heartbeat → `ingest_thing_event` → `catch_new_readings` |
| **Threshold / notification scenario** | Violation → `add_notification`; verify inbox when Manifold channel enabled |
| **Remove community scenario** | Cleanup / subscription teardown |
| **ldds20 / wl03a_lb initiation** | Routers exist; add to `SENSOR_INITIATION_CASES` when ready |
| **CI** | Local only for now |

---

## Related docs

- [`README.md`](README.md) — Manifold integration, bootstrap flow, rulesets, **HA companion**
- [`MEMORY.md` in manifold-home-assistant](../manifold-home-assistant/MEMORY.md) — hub + companion architecture
- [`t/README.md`](t/README.md) — how to run tests, config, writing scenarios
- [`../manifold-api/t/README.md`](../manifold-api/t/README.md) — shared flags, cleanup, parse gate
- [`../manifold-api/MEMORY.md`](../manifold-api/MEMORY.md) — migration history, KRL conventions, manifold-api harness
