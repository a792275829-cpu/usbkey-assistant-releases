import { success } from "./rpc.mjs";
import { pinSession } from "./pin-session.mjs";

function createDeviceMonitor({ readInventory, enqueue = (job) => job(),
  authentication = pinSession, intervalMs = 1000,
  onInventory = () => {}, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let previous = null, timer = null, running = null, disposed = false;
  const subscriptions = new Map();
  function unsubscribe(connection) {
    const subscription = subscriptions.get(connection);
    if (!subscription) return;
    subscription.active = false;
    for (const timer of subscription.timers) clearTimer(timer);
    subscriptions.delete(connection);
  }
  function subscribe(connection, request, delayTime) {
    if (disposed) throw new Error("设备监测已停止");
    if (typeof delayTime !== "number" || !Number.isFinite(delayTime) || delayTime < 0 || delayTime > 60) throw new Error("设备通知延迟需为0到60秒");
    if (!subscriptions.has(connection) && subscriptions.size >= 128) throw new Error("设备监测连接过多");
    unsubscribe(connection);
    subscriptions.set(connection, { connection, request: { requestId: request.requestId,
      requestOrigin: request.requestOrigin, requestVersion: request.requestVersion, lwsObjectId: request.lwsObjectId },
      delayTime, timers: new Set(), active: true });
  }
  function notify(device, pullOut) {
    for (const sub of subscriptions.values()) {
      const response = success(sub.request, { type: device.device_type ?? 47,
        sn: device.device_sn ?? "", pullOut, deviceId: device.device_id });
      const send = () => {
        if (sub.active && !disposed) {
          try { sub.connection.send(response); } catch { unsubscribe(sub.connection); }
        }
      };
      if (sub.delayTime === 0) send();
      else {
        const timer = setTimer(() => { sub.timers.delete(timer); send(); }, sub.delayTime * 1000);
        sub.timers.add(timer); timer.unref?.();
      }
    }
  }
  function scan() {
    if (disposed) return Promise.resolve();
    if (running) return running;
    running = Promise.resolve().then(() => enqueue(async () => {
      if (disposed) return;
      let devices;
      try {
        devices = await readInventory();
        if (!Array.isArray(devices) || devices.some((d) => !d.device_id)) throw new Error("设备枚举结果无效");
      } catch {
        // A read error is not evidence of an unplug. Revoke credentials, keep
        // the last topology, and recover on the next successful observation.
        authentication.invalidate(); return;
      }
      if (disposed) return;
      onInventory(devices);
      authentication.reconcileDevices(devices.map((d) => String(d.device_id)));
      const current = new Map(devices.map((d) => [String(d.device_id), d]));
      if (previous !== null) {
        for (const [id, d] of previous) if (!current.has(id)) notify(d, true);
        for (const [id, d] of current) if (!previous.has(id)) notify(d, false);
      }
      previous = current;
    })).finally(() => { running = null; });
    return running;
  }
  function start() {
    if (disposed || timer !== null) return;
    scan().catch(() => {});
    timer = setInterval(() => scan().catch(() => {}), intervalMs); timer.unref?.();
  }
  function dispose() {
    disposed = true; clearInterval(timer); timer = null;
    for (const connection of subscriptions.keys()) unsubscribe(connection);
    authentication.invalidate();
  }
  return { subscribe, unsubscribe, scan, start, dispose, subscriptionCount: () => subscriptions.size };
}
export { createDeviceMonitor };
