// Business worker for the Rust transport. fd 3 is an inherited private socket;
// stdin/stdout remain reserved for the existing native Keychain channel.
import { Socket } from "node:net";
import { pathToFileURL } from "node:url";
import { dispatch, failure } from "./rpc.mjs";
import { readDeviceInventory, readDeviceStatus, setDeviceProcessRunner } from "./device-client.mjs";
import { createDeviceMonitor } from "./device-monitor.mjs";
import { deviceSelection } from "./device-selection.mjs";
import { pinSession, setPinSession } from "./pin-session.mjs";
import { createNativePinSession } from "./native-pin-session.mjs";
import { createSerialQueue } from "./serial-queue.mjs";
import { audit, bridgeVersion } from "./runtime.mjs";

export function startTransportWorker(socket, { dispatchRequest = dispatch,
  readInventory = readDeviceInventory, readStatus = readDeviceStatus,
  selection = deviceSelection, authentication = pinSession, pinSessionOptions = {} } = {}) {
  const enqueue = createSerialQueue();
  const connections = new Map();
  const helpers = new Map();
  const pins = new Map();
  let helperSequence = 0;
  let pinSequence = 0;
  const monitor = createDeviceMonitor({ readInventory, enqueue, authentication,
    onInventory: (devices) => selection.reconcile(devices) });
  function send(value) {
    if (socket.destroyed) return;
    if (socket.writableLength > 16 * 1024 * 1024) { socket.destroy(); return; }
    socket.write(JSON.stringify(value) + "\n");
  }
  setDeviceProcessRunner((request) => new Promise((resolve, reject) => {
    if (socket.destroyed || helpers.size >= 64) { reject(new Error("设备执行通道不可用")); return; }
    const helperId = ++helperSequence;
    helpers.set(helperId, { resolve, reject });
    send({ helperId, request });
  }));
  setPinSession(createNativePinSession({ ...pinSessionOptions, request: (request) => new Promise((resolve, reject) => {
    if (socket.destroyed || pins.size >= 128) { reject(new Error("认证状态通道不可用")); return; }
    const pinId = ++pinSequence;
    pins.set(pinId, { resolve, reject }); send({ pinId, request });
  }), onFailure: () => socket.destroy() }));
  function connectionFor(id) {
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("连接标识无效");
    if (!connections.has(id)) {
      connections.set(id, { closed: false, send(response) {
        if (!this.closed) send({ connection: id, response });
      } });
    }
    return connections.get(id);
  }
  async function handle(message) {
    const { id, kind, connection: connectionId, body } = message;
    if (Number.isSafeInteger(message.pinId)) {
      const slot = pins.get(message.pinId);
      if (slot) {
        pins.delete(message.pinId);
        if (message.error) slot.reject(new Error(({ stale: "USBKey 状态已改变，请重新操作",
          invalid_pin: "证书密码格式无效", invalid_binding: "缺少认证设备绑定",
          busy: "认证请求过多" })[message.error] ?? "认证状态操作失败"));
        else slot.resolve(message.result);
      }
      return;
    }
    if (Number.isSafeInteger(message.helperId)) {
      const slot = helpers.get(message.helperId);
      if (slot) {
        helpers.delete(message.helperId);
        if (message.error) slot.reject(new Error(helperError(message.error)));
        else slot.resolve(message.result);
      }
      return;
    }
    // Close immediately, even while a PIN dialog or hardware operation is pending.
    if (kind === "close") {
      const connection = connections.get(connectionId);
      if (connection) { connection.closed = true; monitor.unsubscribe(connection); }
      connections.delete(connectionId);
      return;
    }
    let connection;
    if (kind === "rpc") connection = connectionFor(connectionId);
    let status = 200, result;
    try {
      result = await enqueue(async () => {
        if (connection?.closed) throw new Error("连接已关闭");
        switch (kind) {
          case "rpc": {
            let response;
            try { response = await dispatchRequest(body, { monitor, connection, selection, authentication }); }
            catch (error) { response = failure(body, error instanceof Error ? error.message : "请求失败"); }
            audit("rpc_response", { requestId: response.requestId,
              method: String(body?.requestQuery?.function), status: response.responseResult.status });
            return response;
          }
          case "status": return { service: "netca-ft3000gm", version: bridgeVersion,
            ...await readStatus({ selection }) };
          case "selection": {
            try { return { selectedDeviceId: selection.choose(body?.deviceId, await readInventory()) }; }
            catch { status = 400; return { error: "所选设备不可用，请刷新设备列表" }; }
          }
          case "clear":
            await authentication.forgetSavedPins(); audit("pin_store_cleared", {});
            return { cleared: true };
          default: throw new Error("未知内部操作");
        }
      });
    } catch (error) {
      if (kind === "rpc") result = failure(body, error instanceof Error ? error.message : "请求失败");
      else { status = 503; result = kind === "status"
        ? { service: "netca-ft3000gm", deviceFound: false } : {}; }
    }
    send({ id, status, body: result });
  }
  let buffered = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    while (true) {
      const end = buffered.indexOf(10);
      if (end < 0) break;
      if (end > 4 * 1024 * 1024) { socket.destroy(); return; }
      const line = buffered.subarray(0, end); buffered = buffered.subarray(end + 1);
      try { handle(JSON.parse(line.toString("utf8"))).catch(() => socket.destroy()); }
      catch { socket.destroy(); return; }
    }
    if (buffered.length > 4 * 1024 * 1024) socket.destroy();
  });
  socket.on("error", () => {});
  socket.on("close", () => {
    monitor.dispose(); connections.clear();
    for (const slot of helpers.values()) slot.reject(new Error("设备执行通道已关闭"));
    helpers.clear();
    for (const slot of pins.values()) slot.reject(new Error("认证状态通道已关闭"));
    pins.clear();
    // Do not fall back to Node spawning when the Rust supervisor is unavailable.
  });
  monitor.start();
  send({ ready: true });
  return { monitor };
}

function helperError(code) {
  return ({ spawn_failed: "无法启动 FT3000GM 硬件助手", timeout: "USBKey 硬件操作超时",
    output_limit: "USBKey 硬件助手输出超限", invalid_output: "USBKey 硬件助手返回无效结果",
    invalid_request: "USBKey 硬件调用参数无效", queue_full: "USBKey 硬件请求队列已满",
    cancelled: "USBKey 硬件操作已停止", auth_stale: "USBKey 状态已改变，请重新操作" })[code] ?? "USBKey 硬件助手通信失败";
}

if (process.env.USBKEY_RUST_WORKER === "1" && process.argv[1] &&
    import.meta.url === pathToFileURL(process.argv[1]).href) {
  const socket = new Socket({ fd: 3, readable: true, writable: true });
  socket.on("close", () => process.exit(0));
  audit("server_start", { bridgeVersion, mode: "rust-transport-worker", pid: process.pid });
  startTransportWorker(socket);
}
