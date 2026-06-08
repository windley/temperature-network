# MEMORY: sensor-network

Working context for this repo across sessions. For Manifold migration history and
manifold-api harness details, see [`../manifold-api/MEMORY.md`](../manifold-api/MEMORY.md).

## WHERE WE ARE (2026-06-08)

### Summary

Integration tests for the sensor network live in **`sensor-network/t/`**. The harness
reuses manifold-api's Docker/bootstrap stack via sibling-repo imports and `dependsOn` — it
does **not** duplicate the full test infrastructure.

**Automated regression (today):** 3 tests pass in ~15s when Docker is running:
health check, sensor community creation, and lht65 sensor thing initiation.

**Not yet automated:** readings/threshold path, notification delivery.

### Verified working (automated, 2026-06-08)

| Scenario | What it proves |
|----------|----------------|
| `health` | Pico engine reachable over HTTP |
| `sensor community` | `sensor create_community` → Manifold child with `io.picolabs.community` + `io.picolabs.sensor.community`; entry in Manifold `getCommunities` and `getSensorCommunities` |
| `sensor community` (initiation) | `sensor initiation` `{type: lht65}` → thing with Manifold thing RSs + `sensor.thresholds`, `iotplotter`, `dragino`, `lht65.router`; community↔thing subscription |

### Verified working (manual, pre-harness)

See manifold-api MEMORY.md — bootstrap, initiation, community↔thing subscription, readings,
threshold path were exercised manually before this harness existed.

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
```

### What we built (2026-06-08)

| Piece | Purpose |
|-------|---------|
| `t/config.json` | Own mount at `/var/sensor-network`; `manifoldApiPath` + `dependsOn` for manifold-api |
| `t/run.ts` | Parse → Docker → Manifold bootstrap → sensor bootstrap → scenarios → teardown |
| `t/lib/sensor.ts` | `setupSensorNetworkBootstrap()`, `createSensorCommunity()`, `getSensorCommunities()` |
| `t/lib/run-tests.ts` | Local copy of node:test runner (required — see **Gotchas** below) |
| `t/lib/test-context.ts` | Re-exports `getTestState` / `getTestBootstrap` from manifold-api |
| `t/scenarios/*.scenario.ts` | Test scenarios (not `*.test.ts` — see **Gotchas**) |
| `t/scenarios/index.ts` | Barrel import; **sensor scenarios listed before health** |
| `package.json` | `npm test`, `test:parse`, `test:keep`, `test:cleanup` |

### Test run flow

```
npm test
  → parse (sensor-network + manifold-api KRL via dependsOn)
  → one Docker container, both mounts
  → setupManifoldBootstrap()          ← imported from ../manifold-api/t/lib
  → setupSensorNetworkBootstrap()     ← installs io.picolabs.sensor.network_bootstrap on Manifold pico
  → scenarios (node:test)
  → teardown (leave container on failure)
```

Manifold-api's bootstrap and thing/community scenarios are **not** re-run here.

### Commands

```bash
cd sensor-network && npm install
npm test                    # full run (~15s, 2 tests)
npm run test:parse          # krl-compiler on both repos' mounted KRL
npm run test:keep           # leave container up after run
npm run test:cleanup        # remove leftover containers + /tmp pico homes
npm test -- --skip-parse    # Docker + scenarios only
```

Runtime state: `t/.runtime.json` (gitignored).

---

## Reuse pattern (dependsOn + imports)

**`dependsOn` in config** mounts manifold-api into the same container and includes its KRL in
the parse gate. It does **not** automatically share TypeScript code.

**TypeScript reuse:** import helpers from the sibling repo:

```typescript
import { setupManifoldBootstrap } from "../../.manifold-api/t/lib/bootstrap.js";
import { query, signalWait } from "../../.manifold-api/t/lib/engine.js";
import { getManifoldAppEci } from "../../.manifold-api/t/lib/manifold.js";
```

**manifold-api harness change for cross-repo support (2026-06-08):** config paths
(`resolveMountHostPath`, `dependsOn` paths, `runtimePath`) are now relative to whichever
repo's `t/config.json` is loaded, not hardcoded to manifold-api's root. `RuntimeState`
includes `configPath`.

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
owns Docker/bootstrap; the child reads fixtures from `t/.test-context.json`.

Use a **single entry module** (`t/scenarios/index.ts`) so scenarios share in-process state
(e.g. sensor-community → sensor-initiation fixture). Passing multiple files to `node --test`
isolates modules and breaks that chain.

Local copy lives at `sensor-network/t/lib/run-tests.ts` (uses this repo's `node_modules/tsx`).

### 3. Scenario files named `*.scenario.ts`

Files named `*.test.ts` can be auto-executed by tsx/node before the programmatic runner
starts, which breaks registration order when some scenarios import after async bootstrap.
Use `*.scenario.ts` and load via `t/scenarios/index.ts`.

### 4. Import order in `scenarios/index.ts`

Community before initiation (initiation reads the in-process fixture set by community):

```typescript
import "./sensor-community.scenario.js";
import "./sensor-initiation.scenario.js";
import "./health.scenario.js";
```

### 5. `getSensorCommunities` return shape

The KRL function returns a map's `.values()`. The HTTP query may come back as an object, not
an array. `getSensorCommunities()` normalizes with `Object.values()`.

### 6. Parse exclusions

Legacy/broken rulesets excluded from parse gate in `t/config.json`:

- `dotfile_for_temp_network/**`
- `OLD/**` (legacy wovyn stack, duplicate notification RSs, scratch files)

manifold-api exclusions are on the `dependsOn` entry (`OLD/**`, alexa/google assistant, etc.).

---

## KRL files central to tests

| Ruleset | Role in tests |
|---------|---------------|
| `io.picolabs.sensor.network_bootstrap.krl` | Installed on Manifold pico; handles `sensor create_community` |
| `io.picolabs.sensor.community.krl` | Installed on community child by bootstrap's `finish_sensor_community` |
| `io.picolabs.community.krl` | Installed by manifold_pico (via manifold-api mount) |
| Manifold bootstrap RSs | Via `setupManifoldBootstrap()` — not owned by this repo |

Ruleset URLs in container:

```
file:///var/sensor-network/io.picolabs.sensor.network_bootstrap.krl
file:///var/manifold-api/io.picolabs.manifold_pico.krl
```

---

## Still open / next steps

| Item | Notes |
|------|-------|
| **Readings / threshold scenario** | End-to-end after initiation |
| **Notification scenario** | `addNotification` + channel provisioning via bootstrap `community_ready` |
| **Remove community scenario** | Cleanup / subscription teardown |
| **Shared test package** | Optional future: extract common `t/lib` to `@picolabs/pico-test-harness` if more repos need this |
| **CI** | Local only for now |

---

## Related docs

- [`t/README.md`](t/README.md) — how to run tests, config, writing scenarios
- [`../manifold-api/t/README.md`](../manifold-api/t/README.md) — shared flags, cleanup, parse gate
- [`../manifold-api/MEMORY.md`](../manifold-api/MEMORY.md) — migration history, KRL conventions, manifold-api harness phases
