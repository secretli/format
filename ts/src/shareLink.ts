/**
 * A share secret, optionally followed by `!` and the owner's deletion token.
 * Both are 32 bytes, which base64url-encode to 43 characters.
 */
const SHARE_FRAGMENT = /^[A-Za-z0-9_-]{43}(![A-Za-z0-9_-]{43})?$/;

/** Whether a URL fragment (without `#`) has the shape of a share link's. */
export function isShareFragment(fragment: string): boolean {
  return SHARE_FRAGMENT.test(fragment);
}

/** The whole link, as FORMAT.md section 3 writes it; the Go reader uses the same pattern. */
const SHARE_LINK =
  /^(https?):\/\/([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::([0-9]{1,5}))?\/s#([A-Za-z0-9_-]{43})(?:!([A-Za-z0-9_-]{43}))?$/;

/** A share link taken apart. */
export interface ShareLink {
  /** The server the link belongs to, such as https://secretli.app. */
  readonly origin: string;
  readonly secret: string;
  /** Only in the owner's link. */
  readonly deletionToken?: string;
}

/**
 * Takes a link apart as FORMAT.md section 3 says, or returns undefined. It drops spaces,
 * tabs and line breaks around the text and accepts nothing else: no user info, query,
 * percent-encoding or dot segments, and http only for a loopback host. Unlike the URL
 * parser it normalises nothing it would then have to trust.
 */
export function readShareLink(text: string): ShareLink | undefined {
  const m = SHARE_LINK.exec(trimLink(text));
  if (!m) {
    return undefined;
  }
  const [, scheme, rawHost, rawPort, secret, deletionToken] = m;
  let host = rawHost.toLowerCase();
  if (host.startsWith("[")) {
    const address = canonicalIPv6(host.slice(1, -1));
    if (address === undefined) {
      return undefined;
    }
    host = `[${address}]`;
  }
  let port = "";
  if (rawPort !== undefined) {
    const n = Number(rawPort);
    if (n > 65535) {
      return undefined;
    }
    if (!(scheme === "https" && n === 443) && !(scheme === "http" && n === 80)) {
      port = `:${n}`;
    }
  }
  if (scheme === "http" && !isLoopback(host)) {
    return undefined;
  }
  return deletionToken === undefined
    ? { origin: `${scheme}://${host}${port}`, secret }
    : { origin: `${scheme}://${host}${port}`, secret, deletionToken };
}

export type ShareLinkResult =
  | { readonly kind: "share"; readonly fragment: string }
  | { readonly kind: "other-host"; readonly host: string }
  | { readonly kind: "invalid" };

/**
 * Checks a pasted or scanned share link. Only links for `origin` are opened:
 * the share lives on the server that created it, and a scanned code may point
 * anywhere.
 */
export function parseShareLink(text: string, origin: string): ShareLinkResult {
  const link = readShareLink(text);
  if (!link) {
    return { kind: "invalid" };
  }

  if (link.origin !== origin) {
    return { kind: "other-host", host: link.origin.slice(link.origin.indexOf("://") + 3) };
  }

  const fragment =
    link.deletionToken === undefined ? link.secret : `${link.secret}!${link.deletionToken}`;
  return { kind: "share", fragment };
}

/**
 * The text without spaces, tabs and line breaks around it. A loop, not a regular expression:
 * /[ \t\r\n]+$/ takes quadratic time on a long run of them that doesn't end the text.
 */
function trimLink(text: string): string {
  const around = " \t\r\n";
  let start = 0;
  let end = text.length;
  while (start < end && around.includes(text[start])) {
    start++;
  }
  while (end > start && around.includes(text[end - 1])) {
    end--;
  }
  return text.slice(start, end);
}

/** localhost, 127.0.0.0/8 as four decimal numbers without leading zeros, or ::1. */
function isLoopback(host: string): boolean {
  if (host === "localhost" || host === "[::1]") {
    return true;
  }
  const parts = host.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((part) => /^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)
  );
}

/**
 * An IPv6 address of hex digits and colons in its canonical form (RFC 5952): lower case,
 * no leading zeros, the first longest run of two or more zero groups as `::`. Undefined
 * for anything that isn't one, and for IPv4-mapped addresses (::ffff:0:0/96).
 */
function canonicalIPv6(text: string): string | undefined {
  const halves = text.split("::");
  if (halves.length > 2) {
    return undefined;
  }
  const groupsOf = (half: string): number[] | undefined => {
    if (half === "") {
      return [];
    }
    const groups = half.split(":");
    if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
      return undefined;
    }
    return groups.map((g) => Number.parseInt(g, 16));
  };
  const head = groupsOf(halves[0]);
  const tail = halves.length === 2 ? groupsOf(halves[1]) : [];
  if (!head || !tail) {
    return undefined;
  }
  let groups: number[];
  if (halves.length === 2) {
    // "::" stands for at least one zero group.
    if (head.length + tail.length > 7) {
      return undefined;
    }
    groups = [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail];
  } else {
    if (head.length !== 8) {
      return undefined;
    }
    groups = head;
  }
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return undefined;
  }

  let runStart = -1;
  let runLength = 0;
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }
    if (j - i >= 2 && j - i > runLength) {
      runStart = i;
      runLength = j - i;
    }
  }
  const hex = (gs: number[]) => gs.map((g) => g.toString(16)).join(":");
  if (runStart < 0) {
    return hex(groups);
  }
  return `${hex(groups.slice(0, runStart))}::${hex(groups.slice(runStart + runLength))}`;
}
