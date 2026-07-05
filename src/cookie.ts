import { errors, jwtVerify, SignJWT, type JWTPayload } from "jose";

const encoder = new TextEncoder();

export interface VerifiedToken {
  payload: unknown;
  /** signature was valid but the exp claim has passed */
  expired: boolean;
}

export function sign(payload: JWTPayload, secret: string): Promise<string> {
  return new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).sign(encoder.encode(secret));
}

export async function verify(token: string, secret: string): Promise<VerifiedToken | null> {
  try {
    const { payload } = await jwtVerify(token, encoder.encode(secret), {
      algorithms: ["HS256"],
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
