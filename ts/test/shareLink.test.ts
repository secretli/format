import { readFileSync } from "node:fs";
import path from "node:path";
import { parseShareLink, readShareLink } from "../src/shareLink";

interface LinkCase {
  input: string;
  origin?: string;
  secret?: string;
  deletion_token?: string;
  refused?: boolean;
  why?: string;
}

const linkCases: LinkCase[] = JSON.parse(
  readFileSync(path.join(__dirname, "../../spec/vectors/links.json"), "utf8"),
).cases;

describe("the link vectors", () => {
  it.each(linkCases.map((c) => [JSON.stringify(c.input), c] as const))("%s", (_, c) => {
    if (c.refused) {
      expect(readShareLink(c.input)).toBeUndefined();
      expect(parseShareLink(c.input, "https://secretli.app")).toEqual({ kind: "invalid" });
      return;
    }
    const link = readShareLink(c.input);
    expect(link?.origin).toBe(c.origin);
    expect(link?.secret).toBe(c.secret);
    expect(link?.deletionToken ?? "").toBe(c.deletion_token);
    const fragment = c.deletion_token ? `${c.secret}!${c.deletion_token}` : c.secret;
    expect(parseShareLink(c.input, c.origin as string)).toEqual({ kind: "share", fragment });
  });
});

const ORIGIN = "https://secretli.example";
const SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
const TOKEN = "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210_-ZyXwV";

describe("parseShareLink", () => {
  it("accepts a recipient link for this origin", () => {
    expect(parseShareLink(`${ORIGIN}/s#${SECRET}`, ORIGIN)).toEqual({
      kind: "share",
      fragment: SECRET,
    });
  });

  it("accepts an owner link and keeps the deletion token", () => {
    expect(parseShareLink(`${ORIGIN}/s#${SECRET}!${TOKEN}`, ORIGIN)).toEqual({
      kind: "share",
      fragment: `${SECRET}!${TOKEN}`,
    });
  });

  it("ignores surrounding whitespace", () => {
    expect(parseShareLink(`  ${ORIGIN}/s#${SECRET}\n`, ORIGIN).kind).toBe("share");
  });

  it("names the host of a share link for another origin", () => {
    expect(parseShareLink(`https://other.example:8443/s#${SECRET}`, ORIGIN)).toEqual({
      kind: "other-host",
      host: "other.example:8443",
    });
  });

  it("refuses http for a host that is not loopback", () => {
    expect(parseShareLink(`http://secretli.example/s#${SECRET}`, ORIGIN)).toEqual({
      kind: "invalid",
    });
  });

  it("treats a different scheme as another origin", () => {
    expect(parseShareLink(`https://localhost/s#${SECRET}`, "http://localhost")).toEqual({
      kind: "other-host",
      host: "localhost",
    });
  });

  it("compares the origin as the browser writes it", () => {
    expect(
      parseShareLink(`https://[2001:DB8:0::1]:443/s#${SECRET}`, "https://[2001:db8::1]"),
    ).toEqual({
      kind: "share",
      fragment: SECRET,
    });
  });

  it.each([
    ["plain text", "hello world"],
    ["an empty string", ""],
    ["a javascript: URL", `javascript:alert(1)//s#${SECRET}`],
    ["a data: URL", `data:text/html,<p>/s#${SECRET}</p>`],
    ["another path", `${ORIGIN}/share#${SECRET}`],
    ["a trailing slash on the path", `${ORIGIN}/s/#${SECRET}`],
    ["no fragment", `${ORIGIN}/s`],
    ["a key one character short", `${ORIGIN}/s#${SECRET.slice(1)}`],
    ["a key one character long", `${ORIGIN}/s#${SECRET}A`],
    ["standard base64 characters", `${ORIGIN}/s#${SECRET.slice(2)}+/`],
    ["a short deletion token", `${ORIGIN}/s#${SECRET}!${TOKEN.slice(1)}`],
    ["an empty deletion token", `${ORIGIN}/s#${SECRET}!`],
  ])("rejects %s", (_, text) => {
    expect(parseShareLink(text, ORIGIN)).toEqual({ kind: "invalid" });
  });

  it("reads long runs of white space in linear time", () => {
    const run = " \t".repeat(500_000);
    const started = performance.now();
    expect(readShareLink(`x${run}x`)).toBeUndefined();
    expect(readShareLink(`${run}${ORIGIN}/s#${SECRET}${run}`)?.secret).toBe(SECRET);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("rejects a malformed link for another origin without naming its host", () => {
    expect(parseShareLink("https://phish.example/login", ORIGIN)).toEqual({ kind: "invalid" });
  });
});
