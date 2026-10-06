import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

/**
 * This package is the wire format and nothing else: it may use the crypto
 * libraries and its own files, nothing more. The Go module has no dependency
 * but x/crypto and ristretto255 for the same reason.
 */
const FORMAT_DIR = path.resolve(__dirname, "../src");
const ALLOWED_PACKAGES = ["@noble/ciphers/", "@noble/curves/", "@noble/hashes/"];

describe("the format directory", () => {
  it("imports nothing from outside itself", () => {
    const offenders: string[] = [];
    for (const name of readdirSync(FORMAT_DIR)) {
      if (!name.endsWith(".ts")) continue;
      const source = readFileSync(path.join(FORMAT_DIR, name), "utf8");
      for (const match of source.matchAll(/^\s*(?:import|export)[^;]*?from\s+"([^"]+)"/gm)) {
        const specifier = match[1];
        const local = specifier.startsWith("./") && !specifier.includes("..");
        const allowed = ALLOWED_PACKAGES.some((pkg) => specifier.startsWith(pkg));
        if (!local && !allowed) offenders.push(`${name}: ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
