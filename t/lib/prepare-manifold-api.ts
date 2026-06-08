import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

export const MANIFOLD_API_LINK = ".manifold-api";

const DEFAULT_MANIFOLD_API_PATH = "../manifold-api";

export interface PrepareOptions {
  configPath: string;
  manifoldApiPath?: string;
}

export function defaultConfigPath(): string {
  const tDir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(tDir, "..", "config.json");
}

export function repoRootFromConfigPath(configPath: string): string {
  return path.resolve(path.dirname(configPath), "..");
}

/** Parse flags needed before the .manifold-api symlink exists. */
export function parsePrepareArgs(argv: string[]): PrepareOptions {
  let configPath = defaultConfigPath();
  let manifoldApiPath: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config") {
      configPath = path.resolve(argv[++i] ?? "");
      if (!configPath) {
        throw new Error("--config requires a path");
      }
    } else if (arg === "--manifold-api-path") {
      manifoldApiPath = argv[++i];
      if (!manifoldApiPath) {
        throw new Error("--manifold-api-path requires a path");
      }
    }
  }

  return { configPath, manifoldApiPath };
}

function readConfiguredManifoldApiPath(configPath: string): string {
  const raw = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
    manifoldApiPath?: string;
    dependsOn?: Array<{ repo?: string; path?: string }>;
  };

  return (
    raw.manifoldApiPath?.trim() ||
    raw.dependsOn?.find(dep => dep.repo === "manifold-api")?.path?.trim() ||
    DEFAULT_MANIFOLD_API_PATH
  );
}

export function resolveManifoldApiHostPath(opts: PrepareOptions): string {
  const repoRoot = repoRootFromConfigPath(opts.configPath);
  const configured =
    opts.manifoldApiPath?.trim() ||
    process.env.MANIFOLD_API_PATH?.trim() ||
    readConfiguredManifoldApiPath(opts.configPath);

  return path.isAbsolute(configured)
    ? configured
    : path.resolve(repoRoot, configured);
}

/** Symlink repoRoot/.manifold-api → resolved manifold-api checkout for TS imports. */
export function ensureManifoldApiLink(opts: PrepareOptions): string {
  const repoRoot = repoRootFromConfigPath(opts.configPath);
  const target = resolveManifoldApiHostPath(opts);
  const linkPath = path.join(repoRoot, MANIFOLD_API_LINK);

  if (!fs.existsSync(target)) {
    throw new Error(
      `manifold-api not found at ${target}\n` +
        "Set manifoldApiPath in t/config.json, use --manifold-api-path, or export MANIFOLD_API_PATH."
    );
  }

  if (fs.existsSync(linkPath)) {
    const stat = fs.lstatSync(linkPath);
    if (stat.isSymbolicLink()) {
      const current = fs.realpathSync(linkPath);
      if (current === fs.realpathSync(target)) {
        return linkPath;
      }
      fs.unlinkSync(linkPath);
    } else {
      throw new Error(
        `${linkPath} exists and is not a symlink to manifold-api. Remove or rename it.`
      );
    }
  }

  fs.symlinkSync(target, linkPath, "dir");
  return linkPath;
}
