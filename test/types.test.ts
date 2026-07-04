import { describe, expectTypeOf, it } from "vitest";
import { createGate, type Gate, type GateProvider } from "../src/index";

// These assertions are enforced by `pnpm typecheck`; the runtime run is a no-op.
describe("type-level behavior", () => {
  it("flows the provider's Data type into filter without annotations", () => {
    const guildProvider: GateProvider<{ ids: string[] }> = {
      authorizeUrl: () => "https://idp.example/authorize",
      identify: async () => ({ ids: [] }),
    };
    createGate({
      cookieSecret: "s",
      provider: guildProvider,
      filter: (data) => {
        expectTypeOf(data).toEqualTypeOf<{ ids: string[] }>();
        return data.ids.length > 0;
      },
    });
  });

  it("rejects nullish Data at the type level — identify must return Data | null", () => {
    // @ts-expect-error Data must be non-nullish
    type BadUndefined = GateProvider<undefined>;
    // @ts-expect-error Data must be non-nullish
    type BadNull = GateProvider<null>;
  });

  it("createGate returns a plain (request) => Promise<Response | null>", () => {
    const gate = createGate({
      cookieSecret: "s",
      provider: {
        authorizeUrl: () => "https://idp.example/authorize",
        identify: async () => ({}),
      },
    });
    expectTypeOf(gate).toEqualTypeOf<Gate>();
    expectTypeOf(gate).toEqualTypeOf<
      (request: Request) => Promise<Response | null>
    >();
  });
});
