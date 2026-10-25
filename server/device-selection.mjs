import { pinSession } from "./pin-session.mjs";

function createDeviceSelection({ authentication = pinSession } = {}) {
  let selected = null;
  return {
    current: () => selected,
    reconcile(devices) {
      const next = devices.some((d) => d.device_id === selected)
        ? selected : devices[0]?.device_id ?? null;
      if (next !== selected) { selected = next; authentication.invalidate(); }
    },
    choose(deviceId, devices) {
      if (typeof deviceId !== "string" || !devices.some((d) => d.device_id === deviceId)) {
        throw new Error("所选 USBKey 已断开，请刷新设备列表");
      }
      if (selected !== deviceId) { authentication.invalidate(); selected = deviceId; }
      return selected;
    },
  };
}
const deviceSelection = createDeviceSelection();
export { createDeviceSelection, deviceSelection };
