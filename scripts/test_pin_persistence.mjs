import assert from "node:assert/strict";
import { createPinSession } from "../server/pin-session.mjs";
import { createKeychainPinStore, pinAccount } from "../server/pin-store.mjs";

const a = `a1:${"A".repeat(64)}`, replugged = `a2:${"A".repeat(64)}`, b = `b1:${"B".repeat(64)}`;
assert.equal(pinAccount(a), pinAccount(replugged));
assert.notEqual(pinAccount(a), pinAccount(b));
const saved = new Map(); let writes = 0, prompts = 0, attempts = 0;
const store = {
  async read(binding) { return saved.get(pinAccount(binding)) ?? null; },
  async write(binding, pin) { writes++; saved.set(pinAccount(binding), pin); },
  async remove(binding) { saved.delete(pinAccount(binding)); },
  async clear() { saved.clear(); },
};
const sessions = [];
const session = () => {
  const auth = createPinSession({ store, prompt: async () => { prompts++; return "test-only-pin"; } });
  sessions.push(auth); return auth;
};
const operation = async (pin) => { attempts++; assert.equal(pin, "test-only-pin"); return true; };
try {
  const first = session();
  assert.equal(saved.size, 0);
  await first.withAuthentication(a, undefined, operation);
  assert.equal(prompts, 1); assert.equal(writes, 1);
  await first.withAuthentication(a, undefined, operation);
  assert.equal(writes, 1, "memory reuse must not rewrite the keychain");
  first.invalidate();
  const restarted = session();
  await restarted.withAuthentication(replugged, undefined, operation);
  assert.equal(prompts, 1, "restart and replug reuse certificate-bound credentials");
  await restarted.withAuthentication(b, undefined, operation);
  assert.equal(prompts, 2, "another certificate set requires its own credential");
  assert.equal(saved.size, 2);
  restarted.invalidate();
  const before = attempts;
  await assert.rejects(restarted.withAuthentication(a, undefined, async () => {
    attempts++; const error = new Error("PIN rejected"); error.code = "USBKEY_PIN_REJECTED"; throw error;
  }), /PIN rejected/);
  assert.equal(attempts, before + 1, "a remembered bad PIN is never automatically retried");
  assert.equal(saved.has(pinAccount(a)), false);
  assert.equal(saved.has(pinAccount(b)), true, "failure cannot delete another Key's saved PIN");
  await restarted.withAuthentication(a, undefined, operation);
  assert.equal(prompts, 3);
  await restarted.forgetSavedPins();
  assert.equal(saved.size, 0); assert.equal(restarted.hasAuthenticatedSessionPin(), false);
  await restarted.withAuthentication(a, undefined, operation);
  assert.equal(prompts, 4);

  // Forgetting while an authentication is pending must not save its stale PIN.
  let finish;
  const pending = restarted.withAuthentication(a, "test-only-pin", () => new Promise(resolve => { finish = resolve; }));
  await Promise.resolve(); await restarted.forgetSavedPins(); finish(true);
  await assert.rejects(pending, /状态已改变/); assert.equal(saved.size, 0);
  let clock = 0;
  const expiring = createPinSession({ store, now: () => clock,
    prompt: async () => { prompts++; return "test-only-pin"; } });
  sessions.push(expiring);
  await expiring.withAuthentication(a, undefined, operation);
  const beforeExpiry = prompts;
  clock = 10 * 60_000;
  await expiring.withAuthentication(a, undefined, operation);
  assert.equal(prompts, beforeExpiry, "memory expiry must reload keychain without prompting");
  console.log("Persistent PIN binding, replug/restart, one-attempt rejection and forgetting tests PASSED");

  const keychain = createKeychainPinStore({ transport: async (request) => {
    assert.equal(request.account, pinAccount(a));
    return { status: -25300 };
  } });
  assert.equal(await keychain.read(a), null);
  if (process.env.USBKEY_PRIVATE_PIN_CHANNEL !== "1") {
    await assert.rejects(createKeychainPinStore().read(a), /通道未连接/);
  }
} finally { sessions.forEach(s => s.invalidate()); }
