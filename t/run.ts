#!/usr/bin/env tsx
import "./disable-auto-test.mjs";
import { ensureManifoldApiLink, parsePrepareArgs } from "./lib/prepare-manifold-api.js";

const prepareOpts = parsePrepareArgs(process.argv.slice(2));
ensureManifoldApiLink(prepareOpts);

await import("./run-main.js");
