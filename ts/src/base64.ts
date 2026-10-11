export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/**
 * Decodes unpadded base64url in its canonical form only (FORMAT.md section 1): the alphabet
 * and nothing else, no padding, no white space, no bits set past the last byte. atob alone
 * would skip white space and ignore those bits, so two spellings would decode alike.
 */
export function base64UrlDecode(str: string): Uint8Array {
  if (!BASE64URL.test(str) || str.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  // Bits past the last byte are lost in decoding, so only the canonical form encodes back.
  if (base64UrlEncode(bytes) !== str) {
    throw new Error("invalid base64url");
  }
  return bytes;
}
