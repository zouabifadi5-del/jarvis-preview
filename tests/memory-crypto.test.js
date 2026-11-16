import test from "node:test";
import assert from "node:assert/strict";
import {
  encodeMemoryKeyForSetup,
  importMemoryEncryptionKey,
  encryptMemoryText,
  decryptMemoryText,
  MAX_MEMORY_BYTES
} from "../src/auth/memory-crypto.js";

async function makeKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return importMemoryEncryptionKey(encodeMemoryKeyForSetup(raw));
}

const metadata = {
  ownerId: 1,
  recordId: "123e4567-e89b-42d3-a456-426614174000",
  category: "preference",
  keyVersion: 1,
  createdAt: 1700000000
};

test("AES-GCM memory encryption round-trips with a fresh 96-bit nonce", async () => {
  const key = await makeKey();
  const plaintext = "The owner prefers concise responses.";
  const encrypted = await encryptMemoryText(key, { ...metadata, plaintext });
  assert.equal(encrypted.nonce.byteLength, 12);
  assert.ok(encrypted.ciphertext.byteLength >= 16);
  assert.notEqual(new TextDecoder().decode(encrypted.ciphertext), plaintext);
  assert.equal(await decryptMemoryText(key, { ...metadata, ...encrypted }), plaintext);
  const second = await encryptMemoryText(key, { ...metadata, plaintext });
  assert.notDeepEqual([...second.nonce], [...encrypted.nonce]);
});

test("AES-GCM memory encryption rejects tampering and altered associated metadata", async () => {
  const key = await makeKey();
  const encrypted = await encryptMemoryText(key, { ...metadata, plaintext: "synthetic private memory" });
  const tampered = new Uint8Array(encrypted.ciphertext);
  tampered[0] ^= 1;
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, ciphertext: tampered
  }));
  const tamperedNonce = new Uint8Array(encrypted.nonce);
  tamperedNonce[0] ^= 1;
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, nonce: tamperedNonce
  }));
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, category: "fact"
  }));
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, recordId: "123e4567-e89b-42d3-a456-426614174001"
  }));
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, ownerId: 2
  }));
  await assert.rejects(decryptMemoryText(key, {
    ...metadata, ...encrypted, createdAt: metadata.createdAt + 1
  }));
  await assert.rejects(decryptMemoryText(await makeKey(), {
    ...metadata, ...encrypted
  }));
});

test("memory key parsing and plaintext size validation fail closed", async () => {
  await assert.rejects(importMemoryEncryptionKey("not-a-valid-key"), TypeError);
  const key = await makeKey();
  await assert.rejects(encryptMemoryText(key, { ...metadata, plaintext: "" }), TypeError);
  await assert.rejects(encryptMemoryText(key, {
    ...metadata, plaintext: "x".repeat(MAX_MEMORY_BYTES + 1)
  }), RangeError);
});
