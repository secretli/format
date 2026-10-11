/**
 * The Secretli encrypted format, as the web app and the command-line client
 * implement it: key derivation from a share secret, the padded metadata
 * envelope, the bundle (one stream sealed in 64 KiB chunks), and the
 * short-code transfer of a link between devices. See spec/FORMAT.md in
 * the repository for the specification.
 *
 * Everything here is pure. Nothing talks to a server; encrypting and
 * decrypting happen wherever the key is, and the key never leaves there. The
 * transfer runs over a relay the caller provides.
 */
export * from "./base64.js";
export * from "./bundle.js";
export * from "./cpace.js";
export * from "./encryption.js";
export * from "./openBundle.js";
export * from "./shareLink.js";
// Not export *: the WithPrefix variants are for the vectors only (FORMAT.md section 10).
export {
  BUNDLE_PIECE_SIZE,
  BUNDLE_READ_BYTES,
  type BundleEntry,
  type BundleFileInput,
  createStreamBundle,
  cutIntoParts,
  type EncryptStreamOptions,
  encryptStream,
  MAX_BUNDLE_LIST_BYTES,
  plannedBundleSize,
  planStream,
  SEALED_BUNDLE_CHUNK_SIZE,
  type StreamPlan,
} from "./stream.js";
export * from "./transfer.js";
export * from "./transferWords.js";
