// backend/polyfill-webcrypto.js
import { webcrypto } from "node:crypto";

// Falls globalThis.crypto fehlt oder kein subtle hat -> Node WebCrypto setzen
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = webcrypto;
}
