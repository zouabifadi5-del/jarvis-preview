const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
export const MAX_MEMORY_BYTES = 8000;

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError("Memory encryption key must be a 32-byte base64url value");
  }
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/g, "");
}

function memoryAad({ ownerId, recordId, category, keyVersion, schemaVersion = 1, createdAt }) {
  if (!Number.isSafeInteger(ownerId) || ownerId !== 1) throw new TypeError("Invalid memory owner");
  if (typeof recordId !== "string" || !/^[0-9a-f-]{36}$/i.test(recordId)) throw new TypeError("Invalid memory record ID");
  if (!["preference", "fact", "project", "routine", "temporary"].includes(category)) {
    throw new TypeError("Invalid memory category");
  }
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new TypeError("Invalid memory key version");
  if (!Number.isSafeInteger(schemaVersion) || schemaVersion !== 1) throw new TypeError("Invalid memory schema version");
  if (!Number.isSafeInteger(createdAt) || createdAt < 1) throw new TypeError("Invalid memory creation time");
  return encoder.encode([ownerId, recordId, category, keyVersion, schemaVersion, createdAt].join("\n"));
}

export async function importMemoryEncryptionKey(encodedKey) {
  const raw = decodeBase64Url(encodedKey);
  if (raw.byteLength !== AES_KEY_BYTES) throw new TypeError("Invalid memory encryption key length");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptMemoryText(key, {
  plaintext, ownerId = 1, recordId, category, keyVersion = 1, createdAt
}) {
  if (typeof plaintext !== "string" || plaintext.trim().length === 0) {
    throw new TypeError("Memory text must be a non-empty string");
  }
  const plaintextBytes = encoder.encode(plaintext);
  if (plaintextBytes.byteLength > MAX_MEMORY_BYTES) throw new RangeError("Memory text is too large");
  const aad = memoryAad({ ownerId, recordId, category, keyVersion, createdAt });
  const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    plaintextBytes
  );
  return {
    nonce,
    ciphertext: new Uint8Array(ciphertext),
    keyVersion,
    schemaVersion: 1
  };
}

export async function decryptMemoryText(key, {
  ciphertext, nonce, ownerId = 1, recordId, category, keyVersion = 1, schemaVersion = 1, createdAt
}) {
  const encrypted = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext || []);
  const iv = nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce || []);
  if (iv.byteLength !== GCM_NONCE_BYTES || encrypted.byteLength < GCM_TAG_BYTES) {
    throw new TypeError("Invalid encrypted memory record");
  }
  const aad = memoryAad({ ownerId, recordId, category, keyVersion, schemaVersion, createdAt });
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    encrypted
  );
  return decoder.decode(plaintext);
}

export function encodeMemoryKeyForSetup(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== AES_KEY_BYTES) {
    throw new TypeError("Expected exactly 32 random bytes");
  }
  return encodeBase64Url(bytes);
}
