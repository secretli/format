/**
 * Rounds a size up so that it keeps only about log2(log2(size)) significant
 * bits (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
 * Communication with PURBs", 2019). That costs at most 12.5%, and a size at or
 * below a power of two stays at or below it. JavaScript's bit operators are
 * 32-bit and Math.log2 is floating point, so this counts binary digits and
 * divides by powers of two instead, which is exact for safe integers.
 */
export function padme(size: number): number {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("invalid bundle size");
  }
  if (size < 2) {
    return size;
  }
  const e = size.toString(2).length - 1; // floor(log2 size)
  const s = e.toString(2).length; // floor(log2 e) + 1
  const step = 2 ** (e - s);
  return Math.ceil(size / step) * step;
}
