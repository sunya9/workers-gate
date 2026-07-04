import { describe, expect, it } from "vitest";
import { sign, verify } from "../src/cookie";

const SECRET = "test-secret";

function futureExp() {
  return Math.floor(Date.now() / 1000) + 600;
}

describe("sign / verify", () => {
  it("round-trips a signed payload", async () => {
    const token = await sign({ exp: futureExp(), returnTo: "/foo" }, SECRET);
    const result = await verify(token, SECRET);
    expect(result).not.toBeNull();
    expect(result!.expired).toBe(false);
    expect(result!.payload).toMatchObject({ returnTo: "/foo" });
  });

  it("produces standard three-part JWTs with cookie-safe characters", async () => {
    const token = await sign({ exp: futureExp() }, SECRET);
    expect(token).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
  });

  it("returns null for a tampered payload", async () => {
    const token = await sign({ exp: futureExp(), admin: false }, SECRET);
    const [header, , sig] = token.split(".");
    const forged = btoa(JSON.stringify({ exp: futureExp(), admin: true }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    expect(await verify(`${header}.${forged}.${sig}`, SECRET)).toBeNull();
  });

  it("returns null for a wrong secret", async () => {
    const token = await sign({ exp: futureExp() }, SECRET);
    expect(await verify(token, "another-secret")).toBeNull();
  });

  it("returns null for malformed tokens", async () => {
    expect(await verify("garbage", SECRET)).toBeNull();
    expect(await verify("", SECRET)).toBeNull();
    expect(await verify("a.b", SECRET)).toBeNull();
  });

  it("reports expired-but-validly-signed tokens with their payload", async () => {
    const token = await sign(
      { exp: Math.floor(Date.now() / 1000) - 10, returnTo: "/x" },
      SECRET,
    );
    const result = await verify(token, SECRET);
    expect(result).not.toBeNull();
    expect(result!.expired).toBe(true);
    expect(result!.payload).toMatchObject({ returnTo: "/x" });
  });
});
