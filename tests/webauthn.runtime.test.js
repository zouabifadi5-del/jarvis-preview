import { beforeAll, describe, expect, it } from "vitest";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const RP_ID = "example.test";
const ORIGIN = "https://example.test";
const encoder = new TextEncoder();

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function toBase64URL(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64URL(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function uint32(value) {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ]);
}

function derEncodeEcdsaSignature(rawSignature) {
  // WebCrypto returns the P-256 signature as fixed-width r || s.
  const integer = (value) => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    let bytes = value.slice(start);
    if (bytes[0] & 0x80) bytes = concatBytes(new Uint8Array([0]), bytes);
    return concatBytes(new Uint8Array([0x02, bytes.length]), bytes);
  };

  const r = integer(rawSignature.slice(0, 32));
  const s = integer(rawSignature.slice(32, 64));
  const body = concatBytes(r, s);
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

async function makeSyntheticCeremonies() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const x = fromBase64URL(publicJwk.x);
  const y = fromBase64URL(publicJwk.y);

  // COSE EC2 / ES256 public key, encoded as CBOR.
  const cosePublicKey = isoCBOR.encode(new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, x],
    [-3, y]
  ]));

  const credentialId = new Uint8Array([
    0x4a, 0x41, 0x52, 0x56, 0x49, 0x53, 0x2d, 0x54,
    0x45, 0x53, 0x54, 0x2d, 0x43, 0x52, 0x45, 0x44
  ]);
  const credentialIdB64 = toBase64URL(credentialId);
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(RP_ID)));

  const registrationOptions = await generateRegistrationOptions({
    rpName: "JARVIS Synthetic Test",
    rpID: RP_ID,
    userName: "synthetic-owner",
    userID: new Uint8Array([1, 2, 3, 4]),
    attestationType: "none",
    authenticatorSelection: { userVerification: "required" }
  });

  const registrationClientData = encoder.encode(JSON.stringify({
    type: "webauthn.create",
    challenge: registrationOptions.challenge,
    origin: ORIGIN,
    crossOrigin: false
  }));

  const credentialIdLength = new Uint8Array([
    (credentialId.length >>> 8) & 0xff,
    credentialId.length & 0xff
  ]);
  const registrationAuthenticatorData = concatBytes(
    rpIdHash,
    new Uint8Array([0x45]), // user present, user verified, attested credential data
    uint32(0),
    new Uint8Array(16), // synthetic AAGUID
    credentialIdLength,
    credentialId,
    cosePublicKey
  );

  const attestationObject = isoCBOR.encode(new Map([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", registrationAuthenticatorData]
  ]));

  const registrationResponse = {
    id: credentialIdB64,
    rawId: credentialIdB64,
    type: "public-key",
    response: {
      clientDataJSON: toBase64URL(registrationClientData),
      attestationObject: toBase64URL(attestationObject),
      transports: ["internal"]
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {}
  };

  const authenticationOptions = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "required"
  });
  const authenticationClientData = encoder.encode(JSON.stringify({
    type: "webauthn.get",
    challenge: authenticationOptions.challenge,
    origin: ORIGIN,
    crossOrigin: false
  }));
  const authenticationAuthenticatorData = concatBytes(
    rpIdHash,
    new Uint8Array([0x05]), // user present and user verified
    uint32(1)
  );
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", authenticationClientData)
  );
  const signedData = concatBytes(authenticationAuthenticatorData, clientDataHash);
  const rawSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    signedData
  ));
  const signature = derEncodeEcdsaSignature(rawSignature);

  const authenticationResponse = {
    id: credentialIdB64,
    rawId: credentialIdB64,
    type: "public-key",
    response: {
      clientDataJSON: toBase64URL(authenticationClientData),
      authenticatorData: toBase64URL(authenticationAuthenticatorData),
      signature: toBase64URL(signature),
      userHandle: null
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {}
  };

  return {
    registrationOptions,
    registrationResponse,
    authenticationOptions,
    authenticationResponse,
    credential: {
      id: credentialIdB64,
      publicKey: cosePublicKey,
      counter: 0,
      transports: ["internal"]
    }
  };
}

describe("SimpleWebAuthn server runtime compatibility", () => {
  let fixtures;

  beforeAll(async () => {
    fixtures = await makeSyntheticCeremonies();
  });

  it("generates registration options using the Worker runtime crypto APIs", async () => {
    const options = await generateRegistrationOptions({
      rpName: "JARVIS Test",
      rpID: RP_ID,
      userName: "owner-test",
      userID: new Uint8Array([1, 2, 3, 4]),
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required"
      }
    });

    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(options.rp.id).toBe(RP_ID);
    expect(options.user.name).toBe("owner-test");
    expect(options.authenticatorSelection?.residentKey).toBe("required");
    expect(options.authenticatorSelection?.userVerification).toBe("required");
  });

  it("generates authentication options using the Worker runtime crypto APIs", async () => {
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: "required"
    });

    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(options.rpId).toBe(RP_ID);
    expect(options.userVerification).toBe("required");
  });

  it("rejects a malformed synthetic registration response", async () => {
    await expect(
      verifyRegistrationResponse({
        response: {},
        expectedChallenge: "synthetic-challenge",
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects a malformed synthetic authentication response", async () => {
    await expect(
      verifyAuthenticationResponse({
        response: {},
        expectedChallenge: "synthetic-challenge",
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: "synthetic-credential",
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: []
        },
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("verifies a valid synthetic registration ceremony", async () => {
    const result = await verifyRegistrationResponse({
      response: fixtures.registrationResponse,
      expectedChallenge: fixtures.registrationOptions.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    });

    expect(result.verified).toBe(true);
    expect(result.registrationInfo?.credential.id).toBe(fixtures.credential.id);
  });

  it("rejects registration with the wrong challenge", async () => {
    await expect(
      verifyRegistrationResponse({
        response: fixtures.registrationResponse,
        expectedChallenge: "a-different-challenge",
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects registration from the wrong origin", async () => {
    await expect(
      verifyRegistrationResponse({
        response: fixtures.registrationResponse,
        expectedChallenge: fixtures.registrationOptions.challenge,
        expectedOrigin: "https://attacker.example",
        expectedRPID: RP_ID,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects registration for the wrong relying-party ID", async () => {
    await expect(
      verifyRegistrationResponse({
        response: fixtures.registrationResponse,
        expectedChallenge: fixtures.registrationOptions.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: "attacker.example",
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("verifies a valid synthetic authentication ceremony and signature", async () => {
    const result = await verifyAuthenticationResponse({
      response: fixtures.authenticationResponse,
      expectedChallenge: fixtures.authenticationOptions.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: fixtures.credential,
      requireUserVerification: true
    });

    expect(result.verified).toBe(true);
    expect(result.authenticationInfo.userVerified).toBe(true);
    expect(result.authenticationInfo.newCounter).toBe(1);
  });

  it("rejects authentication with the wrong challenge", async () => {
    await expect(
      verifyAuthenticationResponse({
        response: fixtures.authenticationResponse,
        expectedChallenge: "a-different-challenge",
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: fixtures.credential,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects authentication from the wrong origin", async () => {
    await expect(
      verifyAuthenticationResponse({
        response: fixtures.authenticationResponse,
        expectedChallenge: fixtures.authenticationOptions.challenge,
        expectedOrigin: "https://attacker.example",
        expectedRPID: RP_ID,
        credential: fixtures.credential,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects authentication for the wrong relying-party ID", async () => {
    await expect(
      verifyAuthenticationResponse({
        response: fixtures.authenticationResponse,
        expectedChallenge: fixtures.authenticationOptions.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: "attacker.example",
        credential: fixtures.credential,
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects an authentication response with a tampered signature", async () => {
    const signature = fromBase64URL(fixtures.authenticationResponse.response.signature);
    signature[signature.length - 1] ^= 0x01;
    const tamperedResponse = {
      ...fixtures.authenticationResponse,
      response: {
        ...fixtures.authenticationResponse.response,
        signature: toBase64URL(signature)
      }
    };

    const result = await verifyAuthenticationResponse({
      response: tamperedResponse,
      expectedChallenge: fixtures.authenticationOptions.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: fixtures.credential,
      requireUserVerification: true
    });

    expect(result.verified).toBe(false);
  });
});
