// Test-only worker: never opens a USB device or the real login Keychain.
import { Socket } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { startTransportWorker } from "../../server/transport-worker.mjs";
import { dispatch } from "../../server/rpc.mjs";
import { createKeychainPinStore } from "../../server/pin-store.mjs";
import { readPublicCertificate, runProtectedSigner, readDeviceStatus } from "../../server/device-client.mjs";
import { pinSession } from "../../server/pin-session.mjs";

const index = process.argv.indexOf("--fixture-state");
const statePath = process.argv[index + 1];
const state = () => JSON.parse(readFileSync(statePath));
let active = 0, maximum = 0, calls = 0;
let authPrompts = 0, authOperations = 0;
async function operation() {
  active++; maximum = Math.max(maximum, active); calls++;
  try { await new Promise((r) => setTimeout(r, 30)); }
  finally { active--; }
}
// The production auto-start is intentionally bypassed for this injected fixture.
startTransportWorker(new Socket({ fd: 3, readable: true, writable: true }), {
  pinSessionOptions: { prompt: async () => {
    authPrompts++;
    if (state().cancelPrompt) throw new Error("用户取消了 USBKey 证书密码输入");
    await new Promise((resolve) => setTimeout(resolve, 20));
    return "fixture-pin";
  } },
  readInventory: async () => state().devices,
  readStatus: async ({ selection }) => {
    await operation();
    return { deviceFound: true, retries: 5, selectedDeviceId: selection.current(), maximum, calls };
  },
  authentication: { ...pinSession, async forgetSavedPins() {
    await pinSession.forgetSavedPins();
    writeFileSync(statePath, JSON.stringify({ ...state(), cleared: true }));
  } },
  dispatchRequest: async (request, dependencies) => {
    const name = request?.requestQuery?.function;
    if (name === "TestNativeAuth") {
      const param = request.requestQuery.param;
      let outcome = "success", errorCode;
      const run = () => pinSession.withAuthentication(param.binding, param.pin, async (pin) => {
        authOperations++;
        if (param.mode === "forget") await pinSession.forgetSavedPins();
        if (param.mode === "disconnect") await pinSession.reconcileDevices([]);
        if (param.mode === "reject") { const e = new Error("fixture PIN rejected"); e.code = "USBKEY_PIN_REJECTED"; throw e; }
        if (param.mode === "fallback" && pin === null) { const e = new Error("auth required"); e.code = "USBKEY_USER_AUTH_REQUIRED"; throw e; }
        if (["doubleHardware", "staleHardware", "wrongDevice"].includes(param.mode)) {
          if (param.mode === "staleHardware") await pinSession.forgetSavedPins();
          const sign = () => runProtectedSigner(pin, Buffer.from("digest"), "--sign-digest-info",
            { deviceId: param.mode === "wrongDevice" ? "b1" : "a1" });
          await sign();
          if (param.mode === "doubleHardware") await sign();
        }
        if (pin !== null && pin !== "fixture-pin") throw new Error("unexpected fixture PIN");
        return true;
      }, { allowWithoutPin: ["without", "fallback"].includes(param.mode) });
      try { await (param.concurrent ? Promise.all([run(), run()]) : run()); }
      catch (error) { outcome = error.message; errorCode = error.code; }
      return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity:
        { outcome, errorCode, prompts: authPrompts, operations: authOperations,
          authenticated: await pinSession.hasAuthenticatedSessionPin() } };
    }
    if (name === "TestNativeInventory") return { requestId: request.requestId,
      responseResult: { status: 0 }, responseEntity: await readPublicCertificate() };
    if (name === "TestNativeStatus") return { requestId: request.requestId,
      responseResult: { status: 0 }, responseEntity: await readDeviceStatus() };
    if (name === "TestNativeSign") {
      try {
        const bytes = await pinSession.withAuthentication(`a1:${"A".repeat(64)}`, "fixture-pin",
          (pin) => runProtectedSigner(pin, Buffer.from("digest"), "--sign-digest-info", { deviceId: "a1" }));
        return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity: { bytes: bytes.toString("base64") } };
      } catch (error) {
        return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity:
          { message: error.message, code: error.code, result: error.netcaResult, retries: error.retries } };
      }
    }
    if (name === "TestLarge") return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity: { value: "x".repeat(5 * 1024 * 1024) } };
    if (name === "TestKeychain") {
      const pin = await createKeychainPinStore().read(`a1:${"A".repeat(64)}`);
      return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity: { matched: pin === "fixture-pin" } };
    }
    if (["TestFailure", "TestSlow", "TestStats"].includes(name)) {
      await operation();
      if (name === "TestFailure") throw new Error("simulated device failure");
      return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity: { maximum, calls, pid: process.pid } };
    }
    return dispatch(request, dependencies);
  },
});
