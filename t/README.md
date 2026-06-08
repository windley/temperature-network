# Sensor network integration tests

Local TypeScript tests for the sensor-network KRL rulesets. Tests run on your machine
against a **real pico-engine** in a **single Docker container** with both this repo and
**manifold-api** bind-mounted.

This harness reuses the Manifold test infrastructure from the sibling
[`manifold-api`](../manifold-api) repo rather than duplicating Docker, bootstrap, or HTTP
helpers. It adds sensor-specific setup and scenarios on top.

For the full description of parse gate, Docker lifecycle, flags, and cleanup, see
[`manifold-api/t/README.md`](../manifold-api/t/README.md).

## Layout

```
sensor-network/          repo root (KRL rulesets)
.manifold-api/                symlink → local manifold-api checkout (from manifoldApiPath)
sensor-network/t/
  config.json                 mounts + dependsOn
  run.ts                      orchestrator
  setup.ts / teardown.ts      thin wrappers around manifold-api Docker helpers
  lib/
    sensor.ts                 sensor bootstrap install + createSensorCommunity()
    run-tests.ts              node:test runner (must live in this repo — see below)
    test-context.ts           re-exports manifold-api test fixtures
  scenarios/
    index.ts                  imports all scenario modules (order matters)
    health.scenario.ts
    sensor-community.scenario.ts   creates shared community fixture
    sensor-initiation.scenario.ts  one test per sensor type (lht65, lse01, lsn50, …)
```

## What happens when you run tests

```
npm test
  │
  ├─ 1. Parse gate     krl-compiler --verify on sensor-network + manifold-api KRL
  │
  ├─ 2. Docker up      one container, two mounts:
  │                       /var/sensor-network  ← this repo
  │                       /var/manifold-api         ← dependsOn
  │
  ├─ 3. Manifold       setupManifoldBootstrap() from manifold-api
  │       bootstrap    (Tag Registry, Owner, Manifold pico, notification RSs)
  │
  ├─ 4. Sensor         install io.picolabs.sensor.network_bootstrap on Manifold pico
  │       bootstrap
  │
  ├─ 5. Scenarios      node:test scenarios in t/scenarios/
  │
  └─ 6. Teardown       same policy as manifold-api (leave container on failure)
```

Manifold-api's own bootstrap and thing/community scenarios are **not** re-run here. This
suite assumes Manifold is already bootstrapped and only tests sensor-network behavior.

## Prerequisites

1. **Docker** running (`docker ps`).
2. **Node.js 18+**.
3. **A local manifold-api checkout** — default `../manifold-api` (see `manifoldApiPath` below).
   Override with `t/config.json`, `--manifold-api-path`, or `MANIFOLD_API_PATH`.
4. **A pico-engine image** — default `picolabs/pico-engine:latest`.

One-time setup from the **sensor-network repo root**:

```bash
npm install
```

## Running tests

All commands are run from the **sensor-network repo root**, not from `t/`.

| Command | What it does |
|---------|----------------|
| `npm test` | Full run: parse → Docker → bootstrap → scenarios → teardown |
| `npm run test:parse` | Parse gate only (no Docker) |
| `npm run test:keep` | Full run but leave container up afterward |
| `npm run test:cleanup` | Remove all test containers and `/tmp` pico homes for this repo |
| `npm test -- --help` | List flags |

```bash
# Syntax check while editing KRL (both repos)
npm run test:parse

# Inspect after failure
cat t/.runtime.json
open $(node -p "require('./t/.runtime.json').baseUrl")

# Remove leftover containers from test:keep or failed runs
npm run test:cleanup
npm run test:cleanup -- --dry-run
```

Flags and environment variables match manifold-api (`--keep`, `--skip-parse`,
`--skip-docker`, `--retain-logs`, `PICO_ENGINE_IMAGE`), plus:

| Flag / env | Meaning |
|------------|---------|
| `--manifold-api-path <path>` | Local manifold-api directory (overrides config) |
| `MANIFOLD_API_PATH` | Same as `--manifold-api-path` |

See [`manifold-api/t/README.md`](../manifold-api/t/README.md#flags-reference) for shared flags.

Container and pico-home names use this repo's `repoName`:

```
sensor-network-pico-test-<runId>
/tmp/sensor-network-pico-test-<runId>
```

## Configuration (`t/config.json`)

```json
{
  "repoName": "sensor-network",
  "manifoldApiPath": "../manifold-api",
  "mounts": [
    {
      "name": "sensor-network",
      "hostPath": ".",
      "containerPath": "/var/sensor-network"
    }
  ],
  "dependsOn": [
    {
      "repo": "manifold-api",
      "mount": "/var/manifold-api"
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `manifoldApiPath` | Host path to manifold-api (relative to repo root or absolute). Used for Docker mount, parse gate, and a `.manifold-api` symlink for TS imports. Default `../manifold-api`. |
| `mounts` | This repo's KRL, mounted at `/var/sensor-network` |
| `dependsOn` | Extra repo mounted into the **same** container; KRL included in parse gate |
| `dependsOn[].path` | Optional override per dependency; omit for `manifold-api` to use `manifoldApiPath` |
| `parseExclude` | Minimatch patterns skipped during parse (legacy Wovyn rulesets, etc.) |

Ruleset URLs inside the container:

```
file:///var/sensor-network/io.picolabs.sensor.network_bootstrap.krl
file:///var/manifold-api/io.picolabs.manifold_pico.krl
```

## Reusing manifold-api test libs

Import shared helpers from the sibling repo with relative paths:

```typescript
import { query, signalWait } from "../../.manifold-api/t/lib/engine.js";
import { setupManifoldBootstrap } from "../../.manifold-api/t/lib/bootstrap.js";
import { getManifoldAppEci } from "../../.manifold-api/t/lib/manifold.js";
```

What lives where:

| Reused from `manifold-api/t/lib` | Owned by `sensor-network/t` |
|----------------------------------|----------------------------------|
| Docker, parse, CLI, bootstrap | `config.json`, `run.ts` |
| `engine.ts` (query/signal) | `lib/sensor.ts` |
| `bootstrap.ts`, `manifold.ts` | Sensor scenarios |
| `test-context.ts` (fixtures) | `lib/run-tests.ts` (subprocess runner) |

**Important:** `run-tests.ts` lives in this repo so the child process uses this repo's
`node_modules/tsx`. It spawns `node --test` on `t/scenarios/index.ts` only — one module
graph so in-process fixtures (community → initiation) stay shared.

## Sensor-specific helpers (`t/lib/sensor.ts`)

After Manifold bootstrap, `run.ts` calls:

1. `setupSensorNetworkBootstrap(state, bootstrap)` — flush and install
   `io.picolabs.sensor.network_bootstrap` on the Manifold pico.
2. Scenarios use `createSensorCommunity(state, bootstrap, name, description?)` — sends
   `sensor create_community` and waits for the community child plus
   `io.picolabs.sensor.community` ruleset.

Sensor events and queries go through the **Manifold app channel** (`getManifoldAppEci`),
not the UI channel. The UI channel's event policy blocks the `sensor` domain.

## Writing scenarios

Scenarios use Node's built-in test runner (`node:test`) and shared fixtures from
`setTestContext` / `getTestState` / `getTestBootstrap`.

Files are named `*.scenario.ts` (not `*.test.ts`) so tsx does not auto-run them before
bootstrap completes. Add new scenarios to `t/scenarios/index.ts` (community before initiation):

```typescript
import "./sensor-community.scenario.js";
import "./sensor-initiation.scenario.js";
import "./health.scenario.js";
```

Initiation scenarios read shared community context from `t/lib/sensor-fixture.ts`
(populated by the community scenario). To add a sensor type, register it in
`sensor.community` `rids_to_install`, add to `SENSOR_TYPE_RULESETS` in `sensor.ts`,
and append a case to `SENSOR_INITIATION_CASES` in `sensor-initiation.scenario.ts`.

Example skeleton:

```typescript
import { describe, it } from "node:test";
import { getTestBootstrap, getTestState } from "../lib/test-context.js";
import { createSensorCommunity } from "../lib/sensor.js";

describe("my scenario", () => {
  it("does something", async () => {
    const state = getTestState();
    const bootstrap = getTestBootstrap();
    const { entry, uiEci } = await createSensorCommunity(
      state, bootstrap, "My Sensors", "description"
    );
    // assert…
  });
});
```

## Current scenarios

| Scenario | What it verifies |
|----------|------------------|
| `health` | Engine reachable over HTTP |
| `sensor community` | `sensor create_community` → child with `io.picolabs.community` + `io.picolabs.sensor.community`; Manifold subscription |
| `sensor initiation` | Per-type `sensor initiation` (lht65, lse01, lsn50) → thing with Manifold + sensor-network rulesets; community membership |

## Inspecting a failed run

On failure, teardown leaves the container running and writes `t/.runtime.json`. Use the
engine UI at `baseUrl`, read `$PICO_ENGINE_HOME/pico-engine.log`, then clean up:

```bash
npm run test:cleanup
```

Or manually:

```bash
docker rm -f $(node -p "require('./t/.runtime.json').containerName")
rm -rf $(node -p "require('./t/.runtime.json').picoEngineHome")
```
