// Rust owns cached secrets, deadlines, bindings and in-flight authentication
// tokens. This adapter retains only the current operation's PIN and prompt.
import { promptCertificatePin, validatePin } from "./pin-session.mjs";
import { createKeychainPinStore } from "./pin-store.mjs";
import { audit } from "./runtime.mjs";
import { withNativeAuthToken } from "./native-auth-context.mjs";

export function createNativePinSession({ request, prompt = promptCertificatePin,
  store = createKeychainPinStore(), onFailure = () => {} } = {}) {
  let pending = null;
  const call = (operation, fields = {}) => request({ operation, ...fields });
  // These notifications must be enqueued immediately: selection and monitor
  // callbacks are synchronous. IPC ordering fences the next begin/check.
  function notify(operation, fields) {
    const result = call(operation, fields);
    result.catch(onFailure); return result;
  }
  async function withAuthentication(binding, explicitPin, operation, { allowWithoutPin = false } = {}) {
    let token, pin = null, persisted = false;
    try {
      const initial = await call("begin", { binding, ...(explicitPin !== undefined ? { pin: validatePin(explicitPin) } : {}) });
      token = initial.token; pin = initial.pin; persisted = initial.persisted;
      if (pin === null && store) {
        try {
          const remembered = await store.read(binding);
          if (remembered !== null) {
            validatePin(remembered);
            await call("provide", { token, pin: remembered, persisted: true });
            pin = remembered; persisted = true;
          }
        } catch { audit("pin_store_unavailable", { operation: "read" }); }
        await call("check", { token });
      }
      if (pin === null && allowWithoutPin) {
        try {
          const result = await withNativeAuthToken(token, () => operation(null));
          await call("finish_without_pin", { token });
          return result;
        } catch (error) { if (error?.code !== "USBKEY_USER_AUTH_REQUIRED") throw error; }
      }
      if (pin === null) {
        if (pending === null || pending.epoch !== initial.epoch || pending.binding !== binding) {
          const slot = { epoch: initial.epoch, binding,
            promise: Promise.resolve().then(prompt).then(validatePin) };
          pending = slot;
          slot.promise.finally(() => { if (pending === slot) pending = null; }).catch(() => {});
        }
        pin = await pending.promise;
        await call("provide", { token, pin, persisted: false });
      }
      await call("attempt", { token });
      const result = await withNativeAuthToken(token, () => operation(pin));
      await call("check", { token });
      if (store && !persisted) {
        try { await store.write(binding, pin); persisted = true; audit("pin_store_saved", {}); }
        catch { audit("pin_store_unavailable", { operation: "write" }); }
        await call("check", { token });
      }
      await call("commit", { token, persisted });
      return result;
    } catch (error) {
      try {
        const result = token === undefined ? await call("invalidate") : await call("fail", { token });
        if (result.removeSaved && store) {
          try { await store.remove(binding); }
          catch { audit("pin_store_unavailable", { operation: "remove" }); }
        }
      } catch { onFailure(); }
      throw error;
    } finally { pin = null; }
  }
  return { withAuthentication,
    invalidate: () => notify("invalidate"),
    clearCachedCertificatePin: () => notify("clear_cached"),
    clearAuthenticatedSessionPin: () => notify("clear_lease"),
    hasAuthenticatedSessionPin: async () => (await call("status")).authenticated,
    reconcileDevices: (values) => notify("reconcile_devices", { values }),
    reconcileBindings: (values) => notify("reconcile_bindings", { values }),
    async forgetSavedPins() { await call("invalidate"); if (store) await store.clear(); },
  };
}
