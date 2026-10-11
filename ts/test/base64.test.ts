import { base64UrlDecode, base64UrlEncode } from "../src/base64";

describe("base64Url", () => {
  it("round-trips empty array", () => {
    const input = new Uint8Array(0);
    const encoded = base64UrlEncode(input);
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(input);
  });

  it("round-trips arbitrary bytes", () => {
    const input = new Uint8Array([0, 1, 2, 127, 128, 255]);
    const encoded = base64UrlEncode(input);
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(input);
  });

  it("round-trips a 32-byte key", () => {
    const input = crypto.getRandomValues(new Uint8Array(32));
    const encoded = base64UrlEncode(input);
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(input);
  });

  it("produces URL-safe output (no +, /, or =)", () => {
    // Use bytes that would produce +, /, and = in standard base64
    const input = new Uint8Array([251, 255, 254, 63, 62]);
    const encoded = base64UrlEncode(input);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("decodes a known value", () => {
    // "Hello" in base64url is "SGVsbG8"
    const decoded = base64UrlDecode("SGVsbG8");
    expect(new TextDecoder().decode(decoded)).toBe("Hello");
  });
});

describe("base64UrlDecode", () => {
  it.each([
    ["padding", "SGVsbG8="],
    ["white space", "SGVs bG8"],
    ["a line break", "SGVs\nbG8"],
    ["standard base64's +", "a+bc"],
    ["standard base64's /", "a/bc"],
    ["a length that is no number of bytes", "AAAAA"],
    ["bits set past the last byte", "SGVsbG9"],
    ["bits set past the last byte of 32", `${"A".repeat(42)}B`],
    ["a character outside ASCII", "SGVsbG\u00e9"],
  ])("refuses %s", (_, text) => {
    expect(() => base64UrlDecode(text)).toThrow("invalid base64url");
  });

  it("accepts the canonical form of 32 bytes", () => {
    expect(base64UrlDecode(`${"A".repeat(42)}E`)).toHaveLength(32);
  });
});
