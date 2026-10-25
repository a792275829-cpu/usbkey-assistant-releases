import { createHash } from "node:crypto";
import { createInterface } from "node:readline";

function pinAccount(binding) {
  const certSet = String(binding).split(":").slice(1).join(":");
  if (!/^[A-Fa-f0-9]{64}$/.test(certSet)) throw new Error("证书密码绑定无效");
  return createHash("sha256").update(`certificate-set-v1:${certSet.toUpperCase()}`).digest("hex");
}
let sequence = 0, reader;
const pending = new Map();
function privateTransport(value) {
  if (process.env.USBKEY_PRIVATE_PIN_CHANNEL !== "1") return Promise.reject(new Error("钥匙串通道未连接"));
  if (!reader) {
    reader = createInterface({ input: process.stdin });
    process.stdin.unref?.();
    reader.on("line", (line) => {
      if (line.length > 8192) return;
      try {
        const reply = JSON.parse(line);
        if (reply.privateChannel !== "pin-store-v1") return;
        const slot = pending.get(reply.requestId);
        if (slot) { pending.delete(reply.requestId); clearTimeout(slot.timer); slot.resolve(reply); }
      } catch { /* Never log private pipe contents. */ }
    });
  }
  return new Promise((resolve, reject) => {
    const requestId = ++sequence;
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error("钥匙串操作超时")); }, 120000);
    pending.set(requestId, { resolve, timer });
    // This stdout pipe is private to the native parent, never an audit file.
    process.stdout.write(JSON.stringify({ privateChannel: "pin-store-v1", requestId, ...value }) + "\n");
  });
}
function createKeychainPinStore({ transport = privateTransport } = {}) {
  let queue = Promise.resolve();
  function run(operation, binding, pin) {
    const account = operation === "clear" ? undefined : pinAccount(binding);
    const task = queue.then(async () => {
      const result = await transport({ operation, account, pin });
      if (![0, -25300].includes(result.status)) throw new Error("钥匙串操作失败");
      return result.status === -25300 ? null : result;
    });
    queue = task.catch(() => {}); return task;
  }
  return { read: async (binding) => (await run("read", binding))?.pin ?? null,
    write: (binding, pin) => run("write", binding, pin),
    remove: (binding) => run("remove", binding), clear: () => run("clear") };
}
export { createKeychainPinStore, pinAccount };
