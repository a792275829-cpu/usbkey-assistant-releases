import assert from "node:assert/strict";
import { createDeviceMonitor } from "../server/device-monitor.mjs";
import { createPinSession } from "../server/pin-session.mjs";
import { createBridgeServer } from "../server/websocket-server.mjs";
import { createSerialQueue } from "../server/serial-queue.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:tls";
import { once } from "node:events";
import { randomBytes } from "node:crypto";

let devices = [{ device_id: "a1", device_type: 47, device_sn: "token-a" }];
const auth = createPinSession();
const messages = [], delayed = new Map(); let timerId = 0;
const connection = { send: (response) => messages.push(response) };
const monitor = createDeviceMonitor({ readInventory: async () => {
  if (devices === null) throw new Error("unavailable"); return devices;
}, authentication: auth, setTimer: (fn) => { const id = ++timerId; delayed.set(id, fn); return id; },
clearTimer: (id) => delayed.delete(id) });
const request = { requestId: 1, requestVersion: 1, lwsObjectId: "socket-a" };
try {
  await monitor.scan(); monitor.subscribe(connection, request, 0);
  await auth.withAuthentication("a1:certificates", "test-pin", async () => true);
  devices = null; await monitor.scan();
  assert.equal(auth.hasAuthenticatedSessionPin(), false);
  assert.equal(messages.length, 0, "enumeration failure must not invent unplug events");
  devices = []; await monitor.scan();
  assert.equal(messages.length, 1); assert.equal(messages[0].responseEntity.pullOut, true);
  assert.equal(messages[0].responseEntity.sn, "token-a"); assert.equal(messages[0].requestId, 1);
  assert.equal(messages[0].responseVersion, 1); assert.equal(messages[0].lwsObjectId, "socket-a");
  await monitor.scan(); assert.equal(messages.length, 1, "unchanged topology stays quiet");
  devices = [{ device_id: "a2", device_type: 47 }]; await monitor.scan();
  assert.equal(messages[1].responseEntity.pullOut, false);
  monitor.subscribe(connection, { ...request, requestId: 2 }, 2);
  devices = []; await monitor.scan();
  assert.equal(delayed.size, 1); monitor.unsubscribe(connection); assert.equal(delayed.size, 0);
  assert.equal(monitor.subscriptionCount(), 0);
  for (const delay of [-1, NaN, Infinity, 61, "1"]) assert.throws(() => monitor.subscribe(connection, request, delay), /延迟/);
  monitor.subscribe(connection, request, 0);
  monitor.subscribe(connection, { ...request, requestId: 3 }, 0);
  assert.equal(monitor.subscriptionCount(), 1, "resubscription replaces old request state");
  devices = [{ device_id: "b1" }]; await monitor.scan(); assert.equal(messages.at(-1).requestId, 3);
} finally { monitor.dispose(); auth.invalidate(); }

// Polling and RPC must share the hardware queue even across different clients.
const queue = createSerialQueue();
let active = 0, maximum = 0, scans = 0;
const queued = createDeviceMonitor({ enqueue: queue, authentication: createPinSession(),
  readInventory: async () => {
    active++; maximum = Math.max(maximum, active); scans++;
    await new Promise((r) => setTimeout(r, 20)); active--; return [];
  } });
try {
  await Promise.all([queued.scan(), queued.scan(), queue(async () => {
    active++; maximum = Math.max(maximum, active); await new Promise((r) => setTimeout(r, 10)); active--;
  })]);
  assert.equal(scans, 1); assert.equal(maximum, 1);
} finally { queued.dispose(); }

const temp = mkdtempSync(join(tmpdir(), "monitor-wss-"));
let server, socket, wssMonitor;
try {
  execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", join(temp, "key"), "-out", join(temp, "cert")], { stdio: "ignore" });
  const tls = { key: readFileSync(join(temp, "key")), cert: readFileSync(join(temp, "cert")) };
  let topology = [{ device_id: "a1", device_type: 47 }];
  wssMonitor = createDeviceMonitor({ readInventory: async () => topology, intervalMs: 60_000 });
  await wssMonitor.scan();
  server = createBridgeServer({ tls, deviceMonitor: wssMonitor });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  socket = connect({ host: "127.0.0.1", port: server.address().port, ca: tls.cert, servername: "localhost" });
  socket.on("error", () => {});
  await once(socket, "secureConnect");
  let buffer = Buffer.alloc(0), upgraded = false;
  const received = [], waiting = [];
  function deliver(value) { if (waiting.length) waiting.shift()(value); else received.push(value); }
  function next() {
    if (received.length) return Promise.resolve(received.shift());
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("WebSocket event timeout")), 3000);
      waiting.push((value) => { clearTimeout(timeout); resolve(value); });
    });
  }
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    if (!upgraded) {
      const end = buffer.indexOf("\r\n\r\n"); if (end < 0) return;
      assert.match(buffer.subarray(0, end).toString(), /^HTTP\/1.1 101/);
      upgraded = true; buffer = buffer.subarray(end + 4); deliver("upgraded");
    }
    while (buffer.length >= 2) {
      let size = buffer[1] & 127, offset = 2;
      if (size === 126) { if (buffer.length < 4) return; size = buffer.readUInt16BE(2); offset = 4; }
      if (size === 127) { if (buffer.length < 10) return; size = Number(buffer.readBigUInt64BE(2)); offset = 10; }
      if (buffer.length < offset + size) return;
      deliver(JSON.parse(buffer.subarray(offset, offset + size).toString())); buffer = buffer.subarray(offset + size);
    }
  });
  socket.write(["GET / HTTP/1.1", "Host: localhost", "Upgrade: websocket", "Connection: Upgrade",
    `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`, "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Protocol: crypto-jsonrpc-protocol", "Origin: https://pm.gd.csg.cn", "\r\n"].join("\r\n"));
  assert.equal(await next(), "upgraded");
  function send(id) {
    const payload = Buffer.from(JSON.stringify({ requestId: id,
      requestQuery: { function: "MonitorDevice", param: { delayTime: 0 } } }));
    assert.ok(payload.length < 126);
    const mask = randomBytes(4), encoded = Buffer.from(payload);
    for (let i = 0; i < encoded.length; i++) encoded[i] ^= mask[i % 4];
    socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, encoded]));
  }
  send(8); assert.equal((await next()).responseResult.status, 0);
  assert.equal(wssMonitor.subscriptionCount(), 1);
  topology = []; await wssMonitor.scan();
  const event = await next(); assert.equal(event.requestId, 8); assert.equal(event.responseEntity.pullOut, true);
  send(9); await next();
  topology = [{ device_id: "a2", device_type: 47 }]; await wssMonitor.scan();
  const inserted = await next(); assert.equal(inserted.requestId, 9); assert.equal(inserted.responseEntity.pullOut, false);
  socket.end();
  for (let i = 0; i < 100 && wssMonitor.subscriptionCount() !== 0; i++) await new Promise((r) => setTimeout(r, 5));
  assert.equal(wssMonitor.subscriptionCount(), 0, "closing the socket releases subscriptions");
  console.log("Device polling, revocation, delayed cleanup, serial queue and live WSS event tests PASSED");
} finally {
  socket?.destroy(); if (server) await new Promise((r) => server.close(r));
  wssMonitor?.dispose(); rmSync(temp, { recursive: true, force: true });
}
