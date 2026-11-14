import { verifyAuthenticationResponse } from "@simplewebauthn/server";

/**
 * Enforce the application-level binding between a browser response and the
 * credential record selected by the server before cryptographic verification.
 *
 * SimpleWebAuthn verifies the assertion against the credential supplied by the
 * caller; the caller must ensure that credential belongs to response.id/rawId.
 */
export async function verifyStoredCredentialAuthentication({
  response,
  expectedChallenge,
  expectedOrigin,
  expectedRPID,
  credential,
  requireUserVerification = true
}) {
  if (
    !response ||
    typeof response.id !== "string" ||
    typeof response.rawId !== "string" ||
    !credential ||
    typeof credential.id !== "string" ||
    response.id !== response.rawId ||
    response.id !== credential.id
  ) {
    throw new Error("WebAuthn credential ID does not match the stored credential");
  }

  return verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    credential,
    requireUserVerification
  });
}
