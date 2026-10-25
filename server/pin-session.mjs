import { execFileAsync, audit } from "./runtime.mjs";
import { createKeychainPinStore } from "./pin-store.mjs";

async function promptCertificatePin() {
  let result;
  try {
    result = await execFileAsync("/usr/bin/osascript", ["-e",
      'text returned of (display dialog "请输入 USBKey 证书密码以完成本次操作" default answer "" with hidden answer buttons {"取消", "确认"} default button "确认" cancel button "取消" with title "广东电力USBKey助手")'],
    { encoding: "utf8", timeout: 120000, maxBuffer: 4096 });
  } catch { throw new Error("用户取消了 USBKey 证书密码输入"); }
  return result.stdout.replace(/[\r\n]+$/, "");
}
function validatePin(pin) {
  if (typeof pin !== "string" || !pin.length || Buffer.byteLength(pin) > 64 || /[\r\n\0]/.test(pin)) throw new Error("证书密码格式无效");
  return pin;
}

function createPinSession({ prompt = promptCertificatePin, leaseMs = 5 * 60_000,
  promptMs = 60_000, now = Date.now, store = null } = {}) {
  let binding = null, lease = null, cached = null, pending = null, generation = 0, memoryPersisted = false;
  function erase(entry) { if (entry) { clearTimeout(entry.timer); entry.bytes.fill(0); } }
  function clearCachedCertificatePin() { erase(cached); cached = null; }
  function clearAuthenticatedSessionPin() { erase(lease); lease = null; }
  function invalidate() {
    generation += 1; clearCachedCertificatePin(); clearAuthenticatedSessionPin(); binding = null; memoryPersisted = false;
  }
  function bind(next) {
    if (typeof next !== "string" || !next) throw new Error("缺少认证设备绑定");
    if (binding !== next) { invalidate(); binding = next; }
  }
  function read(entry) {
    if (entry && entry.until > now()) return entry.bytes.toString("utf8");
    erase(entry);
    if (lease === entry) lease = null;
    if (cached === entry) cached = null;
    return null;
  }
  function keep(pin, ms, kind) {
    const entry = { bytes: Buffer.from(validatePin(pin)), until: now() + ms };
    entry.timer = setTimeout(() => {
      erase(entry);
      if (kind === "lease" && lease === entry) lease = null;
      if (kind === "cached" && cached === entry) cached = null;
    }, ms);
    entry.timer.unref?.(); return entry;
  }
  async function withAuthentication(next, explicitPin, operation, { allowWithoutPin = false } = {}) {
    bind(next);
    const epoch = generation;
    let attemptedPin = false;
    try {
      let pin = explicitPin !== undefined ? validatePin(explicitPin) : read(lease) ?? read(cached);
      let persisted = explicitPin === undefined && pin !== null && memoryPersisted;
      if (pin === null && store) {
        try {
          const remembered = await store.read(next);
          if (remembered !== null) { pin = validatePin(remembered); persisted = true; }
        } catch { audit("pin_store_unavailable", { operation: "read" }); }
        if (epoch !== generation || binding !== next) throw new Error("USBKey 状态已改变，请重新操作");
      }
      if (pin === null && allowWithoutPin) {
        try {
          const result = await operation(null);
          if (epoch !== generation || binding !== next) throw new Error("USBKey 状态已改变，请重新操作");
          return result;
        }
        catch (error) { if (error?.code !== "USBKEY_USER_AUTH_REQUIRED") throw error; }
      }
      if (pin === null) {
        if (pending === null || pending.epoch !== epoch) {
          const slot = { epoch, promise: Promise.resolve().then(prompt).then(validatePin) };
          pending = slot;
          slot.promise.finally(() => { if (pending === slot) pending = null; }).catch(() => {});
        }
        pin = await pending.promise;
      }
      if (epoch !== generation || binding !== next) throw new Error("USBKey 状态已改变，请重新操作");
      attemptedPin = true;
      const result = await operation(pin);
      if (epoch !== generation || binding !== next) throw new Error("USBKey 状态已改变，请重新操作");
      if (store && !persisted) {
        try { await store.write(next, pin); persisted = true; audit("pin_store_saved", {}); }
        catch { audit("pin_store_unavailable", { operation: "write" }); }
        if (epoch !== generation || binding !== next) throw new Error("USBKey 状态已改变，请重新操作");
      }
      // Only a fully verified operation creates a lease. A rejected cached PIN
      // is never retried automatically: one request consumes at most one try.
      clearCachedCertificatePin(); clearAuthenticatedSessionPin();
      cached = keep(pin, promptMs, "cached"); lease = keep(pin, leaseMs, "lease");
      memoryPersisted = persisted;
      return result;
    } catch (error) {
      invalidate();
      if (attemptedPin && store) {
        try { await store.remove(next); }
        catch { audit("pin_store_unavailable", { operation: "remove" }); }
      }
      throw error;
    }
  }
  return { withAuthentication, invalidate, clearCachedCertificatePin, clearAuthenticatedSessionPin,
    async forgetSavedPins() { invalidate(); if (store) await store.clear(); },
    hasAuthenticatedSessionPin: () => read(lease) !== null,
    reconcileDevices(ids) { if (binding !== null && !ids.includes(binding.split(":")[0])) invalidate(); },
    reconcileBindings(bindings) { if (binding !== null && !bindings.includes(binding)) invalidate(); } };
}
let implementation = createPinSession({ store: createKeychainPinStore() });
// Stable facade also updates device selection's already-captured reference.
const pinSession = Object.fromEntries(Object.keys(implementation).map((name) =>
  [name, (...args) => implementation[name](...args)]));
function setPinSession(next) { implementation.invalidate(); implementation = next; }
const { clearCachedCertificatePin, clearAuthenticatedSessionPin, hasAuthenticatedSessionPin } = pinSession;
export { createPinSession, pinSession, setPinSession, promptCertificatePin, validatePin,
  clearCachedCertificatePin, clearAuthenticatedSessionPin, hasAuthenticatedSessionPin };
