import { describe, expect, it } from "vitest";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";

describe("SimpleWebAuthn server runtime compatibility", () => {
  it("generates registration options using the Worker runtime crypto APIs", async () => {
    const options = await generateRegistrationOptions({
      rpName: "JARVIS Test",
      rpID: "example.test",
      userName: "owner-test",
      userID: new Uint8Array([1, 2, 3, 4]),
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required"
      }
    });

    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(options.rp.id).toBe("example.test");
    expect(options.user.name).toBe("owner-test");
    expect(options.authenticatorSelection?.residentKey).toBe("required");
    expect(options.authenticatorSelection?.userVerification).toBe("required");
  });

  it("generates authentication options using the Worker runtime crypto APIs", async () => {
    const options = await generateAuthenticationOptions({
      rpID: "example.test",
      userVerification: "required"
    });

    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(options.rpId).toBe("example.test");
    expect(options.userVerification).toBe("required");
  });
  
  it("rejects a malformed synthetic registration response", async () => {
    await expect(
      verifyRegistrationResponse({
        response: {},
        expectedChallenge: "synthetic-challenge",
        expectedOrigin: "https://example.test",
        expectedRPID: "example.test",
        requireUserVerification: true
      })
    ).rejects.toThrow();
  });

  it("rejects a malformed synthetic authentication response", async () => {
    await expect(
      verifyAuthenticationResponse({
        response: {},
        expectedChallenge: "synthetic-challenge",
        expectedOrigin: "https://example.test",
        expectedRPID: "example.test",
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
});
