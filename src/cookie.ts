import { errors, jwtVerify, SignJWT, type JWTPayload } from "jose";

const encoder = new TextEncoder();

export interface VerifiedToken {
  payload: unknown;
  /** signature was valid but the exp claim has passed */
  expired: boolean;
}

export function sign(payload: JWTPayload, secret: string, audience?: string): Promise<string> {
  const jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256" });
  if (audience) jwt.setAudience(audience);
  return jwt.sign(encoder.encode(secret));
}

export async function verify(
  token: string,
  secret: string,
  audience?: string,
): Promise<VerifiedToken | null> {
  try {
    const { payload } = await jwtVerify(token, encoder.encode(secret), {
      algorithms: ["HS256"],
      ...(audience ? { audience } : {}),
    });
    return { payload, expired: false };
  } catch (error) {
    // expired-but-valid must stay distinguishable: it drives silent re-auth
    if (error instanceof errors.JWTExpired) {
      return { payload: error.payload, expired: true };
    }
    return null;
  }
}
