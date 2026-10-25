import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect } from "node:tls";
import { request as httpsRequest } from "node:https";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { pinAccount } from "../server/pin-store.mjs";

const temp = mkdtempSync(join(tmpdir(), "rust-transport-"));
const sockets = new Set();
let child, workerPid;
let transportErrors = "";
const fixture = join(temp, "state.json");
const deadline = (promise, ms = 5000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("test timeout")), ms);
  promise.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
});

function frame(text, { opcode = 1, final = true, masked = true, rsv = false } = {}) {
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text);
  let header;
  if (bytes.length < 126) header = Buffer.from([0, bytes.length]);
  else if (bytes.length <= 65535) { header = Buffer.alloc(4); header[1] = 126; header.writeUInt16BE(bytes.length, 2); }
  else { header = Buffer.alloc(10); header[1] = 127; header.writeBigUInt64BE(BigInt(bytes.length), 2); }
  header[0] = (final ? 128 : 0) | (rsv ? 64 : 0) | opcode;
  if (!masked) return Buffer.concat([header, bytes]);
  header[1] |= 128;
  const mask = randomBytes(4), payload = Buffer.from(bytes);
  for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
  return Buffer.concat([header, mask, payload]);
}

try {
  execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", join(temp, "key"),
    "-out", join(temp, "cert")], { stdio: "ignore" });
  const certificate = execFileSync("/usr/bin/openssl", ["x509", "-in", join(temp, "cert"), "-outform", "DER"]).toString("base64");
  writeFileSync(fixture, JSON.stringify({ devices: [{ device_id: "a1", device_type: 47 }], certificate, mode: "success" }));
  const helper = join(temp, "helper.py"), helperCalls = join(temp, "helper-calls.jsonl");
  writeFileSync(helper, `#!/usr/bin/python3
import sys,json,os,base64,time
state=json.load(open(${JSON.stringify(fixture)}))
data=sys.stdin.read()
with open(${JSON.stringify(helperCalls)},'a') as log:
    log.write(json.dumps({'pid':os.getpid(),'parent':os.getppid(),'args':sys.argv[1:],'inputLines':len(data.splitlines()),'privateEnv':os.getenv('USBKEY_PRIVATE_PIN_CHANNEL')})+'\\n')
op=sys.argv[1]
if state.get('mode')=='hang' and op=='--sign-digest-info': time.sleep(30)
if op=='--list-devices': out={'devices':state['devices']}
elif op=='--include-certificate': out={'device_found':True,'device_id':'a1','certificate_count':1,'certificates':[{'file_id':'3001','encode':state['certificate']}]}
elif op=='--pin-status': out={'retries':5}
elif state.get('mode')=='badpin':
    print(json.dumps({'pin_verified':False,'verify_sw':'63C2','retries':2})); sys.exit(4)
else: out={'signed':True,'signature_base64':base64.b64encode(b'fixture-signature').decode()}
print(json.dumps(out))
`); chmodSync(helper, 0o700);
  child = spawn(resolve(process.env.RUST_TRANSPORT_BIN ?? "rust-transport/target/debug/usbkey-transport"), [
    "--port", "0", "--cert", join(temp, "cert"), "--key", join(temp, "key"), "--node", process.execPath,
    "--worker", resolve("tests/fixtures/rust-transport-worker.mjs"), "--fixture-state", fixture,
    "--log", join(temp, "audit.log"),
    "--probe", helper, "--signer", helper,
  ], { env: { ...process.env, USBKEY_PRIVATE_PIN_CHANNEL: "1", USBKEY_RUST_WORKER: "0" }, stdio: ["pipe", "pipe", "pipe"] });
  // Fixture uses the same inherited stdin/stdout path as the native app.
  let privateBuffer = "", keychainRequests = 0;
  const keychain = new Map([[pinAccount(`a1:${"A".repeat(64)}`), "fixture-pin"]]);
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (text) => {
    privateBuffer += text;
    while (privateBuffer.includes("\n")) {
      const end = privateBuffer.indexOf("\n"), line = privateBuffer.slice(0, end); privateBuffer = privateBuffer.slice(end + 1);
      const message = JSON.parse(line);
      if (message.privateChannel === "pin-store-v1") {
        keychainRequests++;
        let status = 0, pin;
        if (JSON.parse(readFileSync(fixture)).storeUnavailable) status = -25291;
        else if (message.operation === "read") { pin = keychain.get(message.account); if (pin === undefined) status = -25300; }
        else if (message.operation === "write") keychain.set(message.account, message.pin);
        else if (message.operation === "remove") keychain.delete(message.account);
        else if (message.operation === "clear") keychain.clear();
        child.stdin.write(JSON.stringify({ privateChannel: "pin-store-v1", requestId: message.requestId, status, pin }) + "\n");
      }
    }
  });
  let stderr = "";
  const port = await deadline(new Promise((resolve, reject) => {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (data) => { stderr += data; transportErrors += data; const match = stderr.match(/listening on 127\.0\.0\.1:(\d+)/); if (match) resolve(Number(match[1])); });
    child.once("exit", (code) => reject(new Error(`transport exited ${code}: ${stderr}`)));
    child.once("error", reject);
  }), 15000);
  const tls = { host: "127.0.0.1", port, ca: readFileSync(join(temp, "cert")), servername: "localhost" };
  function http(path, { method = "GET", headers = {}, body = "" } = {}) {
    return deadline(new Promise((resolve, reject) => {
      const req = httpsRequest({ ...tls, path, method, headers }, (res) => {
        let text = ""; res.setEncoding("utf8"); res.on("data", (s) => { text += s; });
        res.on("end", () => resolve({ status: res.statusCode, body: text, headers: res.headers }));
      });
      req.setTimeout(4000, () => req.destroy(new Error("HTTP timeout"))); req.on("error", reject); req.end(body);
    }));
  }
  async function ws({ origin = "https://pm.gd.csg.cn", protocol = "crypto-jsonrpc-protocol", version = "13", key, head } = {}) {
    const socket = connect(tls); sockets.add(socket); socket.on("error", () => {});
    await deadline(once(socket, "secureConnect"));
    let buffer = Buffer.alloc(0), upgraded = false, handshake;
    const received = [], waiting = [];
    const deliver = (value) => waiting.length ? waiting.shift()(value) : received.push(value);
    const next = () => deadline(received.length ? Promise.resolve(received.shift()) : new Promise((r) => waiting.push(r)));
    const closed = new Promise((r) => socket.once("close", () => { sockets.delete(socket); deliver({ closed: true }); r(); }));
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const end = buffer.indexOf("\r\n\r\n"); if (end < 0) return;
        handshake = buffer.subarray(0, end).toString(); buffer = buffer.subarray(end + 4);
        upgraded = true; deliver({ handshake });
        if (!handshake.startsWith("HTTP/1.1 101")) return;
      }
      while (buffer.length >= 2) {
        let size = buffer[1] & 127, offset = 2;
        if (size === 126) { if (buffer.length < 4) return; size = buffer.readUInt16BE(2); offset = 4; }
        else if (size === 127) { if (buffer.length < 10) return; size = Number(buffer.readBigUInt64BE(2)); offset = 10; }
        if (buffer.length < offset + size) return;
        const opcode = buffer[0] & 15, payload = buffer.subarray(offset, offset + size);
        deliver({ opcode, payload, ...(opcode === 1 ? { json: JSON.parse(payload.toString()) } : {}) });
        buffer = buffer.subarray(offset + size);
      }
    });
    socket.write(Buffer.concat([Buffer.from(["GET / HTTP/1.1", `Host: localhost:${tls.port}`, "Connection: Upgrade", "Upgrade: websocket",
      `Sec-WebSocket-Key: ${key ?? randomBytes(16).toString("base64")}`, `Sec-WebSocket-Version: ${version}`,
      `Sec-WebSocket-Protocol: ${protocol}`, `Origin: ${origin}`, "\r\n"].join("\r\n")), head ?? Buffer.alloc(0)]));
    const result = await next();
    return { socket, next, closed, handshake: result.handshake,
      send(value, options) { socket.write(frame(typeof value === "string" ? value : JSON.stringify(value), options)); } };
  }
  const request = (id, name, param = {}) => ({ requestId: id, requestVersion: 1, lwsObjectId: "test-connection", requestOrigin: "fixture",
    requestQuery: { function: name, param } });
  const health = await http("/health"); assert.equal(health.body, "netca-ft3000gm"); assert.equal(health.headers["cache-control"], "no-store");
  assert.equal((await http("/status", { headers: { Origin: "https://example.com" } })).status, 403);
  for (const path of ["/selection", "/pin-cache/clear"]) {
    assert.equal((await http(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: "null" } })).status, 403);
    assert.equal((await http(path, { method: "POST" })).status, 403);
  }
  assert.equal((await http("/selection", { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(1025) })).status, 413);
  assert.equal((await http("/selection", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" })).status, 400);
  for (const options of [{ origin: "https://example.com" }, { protocol: "other" }, { version: "12" }, { key: "invalid" }]) {
    const denied = await ws(options); assert.ok(!denied.handshake.startsWith("HTTP/1.1 101")); denied.socket.destroy();
  }
  const a = await ws({ head: frame(JSON.stringify(request(1, "TestFailure"))) });
  assert.match(a.handshake, /Sec-WebSocket-Protocol: crypto-jsonrpc-protocol/i);
  const b = await ws(); b.send(request(2, "TestSlow"));
  const [failure, success, status] = await Promise.all([a.next(), b.next(), http("/status")]);
  assert.equal(failure.json.responseResult.status, -11000); assert.equal(failure.json.lwsObjectId, "test-connection");
  assert.equal(success.json.responseResult.status, 0); assert.equal(JSON.parse(status.body).maximum, 1);
  workerPid = success.json.responseEntity.pid;
  a.send(request(3, "GetVersionInfo1")); assert.equal((await a.next()).json.requestId, 3);
  a.send("{"); assert.equal((await a.next()).json.responseResult.status, -11000);
  // Fragmented UTF-8 text is reassembled by the mature protocol implementation.
  const fragmented = JSON.stringify(request(4, "GetVersionInfo1", { note: "中文" }));
  a.socket.write(frame(fragmented.slice(0, 25), { final: false }));
  a.socket.write(frame(fragmented.slice(25), { opcode: 0 }));
  assert.equal((await a.next()).json.requestId, 4);
  a.send("ping", { opcode: 9 }); const pong = await a.next(); assert.equal(pong.opcode, 10); assert.equal(pong.payload.toString(), "ping");
  a.send(request(5, "TestKeychain")); assert.equal((await a.next()).json.responseEntity.matched, true); assert.equal(keychainRequests, 1);
  a.send(request(10, "TestNativeInventory")); assert.equal((await a.next()).json.responseEntity.devices[0].device_id, "a1");
  a.send(request(11, "TestNativeStatus")); assert.equal((await a.next()).json.responseEntity.retries, 5);
  a.send(request(12, "TestNativeSign")); assert.equal(Buffer.from((await a.next()).json.responseEntity.bytes, "base64").toString(), "fixture-signature");
  const beforeFailure = readFileSync(helperCalls, "utf8").trim().split("\n").length;
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), mode: "badpin" }));
  a.send(request(13, "TestNativeSign")); const pinFailure = (await a.next()).json.responseEntity;
  assert.equal(pinFailure.code, "USBKEY_PIN_REJECTED"); assert.equal(pinFailure.result, -5); assert.equal(pinFailure.retries, 2);
  const helperLog = readFileSync(helperCalls, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(helperLog.length, beforeFailure + 1, "rejected PIN must not retry or fall back to Node");
  assert.ok(helperLog.every((call) => call.parent === child.pid && call.privateEnv === null));
  assert.equal(JSON.stringify(helperLog).includes("fixture-pin"), false);
  a.send(request(7, "TestLarge")); assert.equal((await a.next()).json.responseEntity.value.length, 5 * 1024 * 1024);
  // Native session conformance through real Rust IPC and a simulated Keychain.
  const binding = (letter) => `a1:${letter.repeat(64)}`;
  let authId = 1000;
  async function authenticate(letter = "B", options = {}) {
    a.send(request(authId++, "TestNativeAuth", { binding: binding(letter), ...options }));
    return (await a.next()).json.responseEntity;
  }
  const firstAuth = await authenticate(); assert.equal(firstAuth.outcome, "success"); assert.equal(firstAuth.prompts, 1); assert.equal(firstAuth.authenticated, true);
  const reuseAuth = await authenticate(); assert.equal(reuseAuth.prompts, 1); assert.equal(reuseAuth.operations, firstAuth.operations + 1);
  a.send(request(authId++, "ClearPwdCache")); assert.equal((await a.next()).json.responseResult.status, 0);
  assert.equal((await authenticate()).prompts, 1, "clear prompt cache preserves native authentication lease");
  const otherAuth = await authenticate("C"); assert.equal(otherAuth.prompts, 2);
  const restoredAuth = await authenticate(); assert.equal(restoredAuth.prompts, 2, "binding change reloads saved PIN without another prompt");
  const rejectedAuth = await authenticate("B", { mode: "reject" });
  assert.equal(rejectedAuth.errorCode, "USBKEY_PIN_REJECTED"); assert.equal(rejectedAuth.operations, restoredAuth.operations + 1);
  assert.equal(rejectedAuth.authenticated, false); assert.equal(keychain.has(pinAccount(binding("B"))), false);
  assert.equal(keychain.has(pinAccount(binding("C"))), true, "failure must not delete another certificate set");
  assert.equal((await authenticate()).prompts, 3);
  const noPinAuth = await authenticate("D", { mode: "without" }); assert.equal(noPinAuth.prompts, 3); assert.equal(noPinAuth.authenticated, false);
  const fallbackAuth = await authenticate("E", { mode: "fallback" }); assert.equal(fallbackAuth.prompts, 4);
  assert.equal(fallbackAuth.operations, noPinAuth.operations + 2, "only explicit auth-required permits PIN fallback");
  const forgetting = await authenticate("E", { mode: "forget" }); assert.match(forgetting.outcome, /状态已改变/);
  assert.equal(keychain.size, 0); assert.equal(forgetting.authenticated, false);
  const disconnected = await authenticate("F", { mode: "disconnect" }); assert.match(disconnected.outcome, /状态已改变/);
  assert.equal(keychain.has(pinAccount(binding("F"))), false);
  const merged = await authenticate("1", { concurrent: true }); assert.equal(merged.prompts, disconnected.prompts + 1);
  assert.equal(merged.operations, disconnected.operations + 2, "same-epoch concurrent callers share one prompt");
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), cancelPrompt: true }));
  const cancelled = await authenticate("2"); assert.match(cancelled.outcome, /取消/); assert.equal(cancelled.operations, merged.operations);
  assert.equal(cancelled.authenticated, false);
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), cancelPrompt: false, storeUnavailable: true }));
  const unavailable = await authenticate("3"); assert.equal(unavailable.outcome, "success"); assert.equal(unavailable.authenticated, true);
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), storeUnavailable: false }));
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), mode: "success" }));
  const hardwareCalls = () => readFileSync(helperCalls, "utf8").trim().split("\n").length;
  const beforeFencing = hardwareCalls();
  assert.match((await authenticate("4", { pin: "fixture-pin", mode: "doubleHardware" })).outcome, /状态已改变/);
  assert.equal(hardwareCalls(), beforeFencing + 1, "native token permits only one PIN-bearing hardware launch");
  assert.match((await authenticate("5", { pin: "fixture-pin", mode: "staleHardware" })).outcome, /状态已改变/);
  assert.match((await authenticate("6", { pin: "fixture-pin", mode: "wrongDevice" })).outcome, /状态已改变/);
  assert.equal(hardwareCalls(), beforeFencing + 1, "invalidated or wrong-device tokens must not start a helper");
  a.send(request(6, "MonitorDevice")); assert.equal((await a.next()).json.requestId, 6);
  const selection = await http("/selection", { method: "POST", headers: { "Content-Type": "application/json; charset=utf-8" }, body: '{"deviceId":"a1"}' });
  assert.equal(JSON.parse(selection.body).selectedDeviceId, "a1");
  writeFileSync(fixture, JSON.stringify({ devices: [] }));
  const event = await a.next(); assert.equal(event.json.requestId, 6); assert.equal(event.json.responseEntity.pullOut, true);
  assert.equal((await http("/pin-cache/clear", { method: "POST", headers: { "Content-Type": "application/json" } })).status, 200);
  assert.equal(JSON.parse(readFileSync(fixture)).cleared, true);
  for (const options of [{ masked: false }, { rsv: true }, { opcode: 9 }]) {
    const bad = await ws(); bad.send(options.opcode === 9 ? "x".repeat(126) : "{}", options);
    const result = await bad.next(); assert.ok(result.closed || result.opcode === 8); bad.socket.destroy();
  }
  const oversized = await ws(); oversized.socket.write(frame(Buffer.alloc(1024 * 1024 + 1, 32)));
  const rejected = await oversized.next(); assert.ok(rejected.closed || rejected.opcode === 8); oversized.socket.destroy();
  const closing = await ws(); closing.socket.write(frame(Buffer.from([3, 232]), { opcode: 8 }));
  assert.equal((await closing.next()).opcode, 8); await deadline(closing.closed);
  // Disconnect during a request must not exhaust IPC slots or retain subscriptions.
  for (let i = 0; i < 70; i++) { const c = await ws(); c.send(request(100 + i, "TestSlow")); c.socket.destroy(); }
  await new Promise((r) => setTimeout(r, 2400));
  b.send(request(300, "TestStats")); assert.equal((await b.next()).json.responseResult.status, 0);
  assert.equal((await http("/health")).status, 200);
  // A failed worker must take down the transport, not leave a healthy-looking listener.
  writeFileSync(fixture, JSON.stringify({ ...JSON.parse(readFileSync(fixture)), mode: "hang" }));
  const previousHelpers = readFileSync(helperCalls, "utf8").trim().split("\n").length;
  b.send(request(301, "TestNativeSign"));
  const activeHelperPid = await deadline((async () => {
    while (true) {
      const entries = readFileSync(helperCalls, "utf8").trim().split("\n");
      if (entries.length > previousHelpers) return JSON.parse(entries.at(-1)).pid;
      await new Promise((r) => setTimeout(r, 10));
    }
  })());
  process.kill(workerPid, "SIGKILL");
  await deadline(once(child, "exit")); assert.notEqual(child.exitCode, 0);
  assert.throws(() => process.kill(activeHelperPid, 0), { code: "ESRCH" }, "worker crash must kill and reap the active hardware helper");
  assert.equal(readFileSync(join(temp, "audit.log"), "utf8").includes("fixture-pin"), false);

  // Also exercise the real worker entrypoint with an empty-device stub, not hardware.
  const probe = join(temp, "empty-probe");
  writeFileSync(probe, '#!/bin/sh\nprintf \'{"devices":[]}\\n\'\n'); chmodSync(probe, 0o700);
  child = spawn(resolve(process.env.RUST_TRANSPORT_BIN ?? "rust-transport/target/debug/usbkey-transport"), [
    "--port", "0", "--cert", join(temp, "cert"), "--key", join(temp, "key"), "--node", process.execPath,
    "--worker", resolve("server/transport-worker.mjs"), "--probe", probe, "--log", join(temp, "production-audit.log"),
  ], { stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.resume();
  tls.port = await deadline(new Promise((resolve, reject) => {
    let output = "";
    child.stderr.on("data", (chunk) => { output += chunk; transportErrors += chunk;
      const match = output.match(/listening on 127\.0\.0\.1:(\d+)/); if (match) resolve(Number(match[1])); });
    child.once("exit", () => reject(new Error(output))); child.once("error", reject);
  }));
  assert.equal((await http("/health")).status, 200);
  const productionStatus = await http("/status"); assert.equal(productionStatus.status, 200);
  assert.equal(JSON.parse(productionStatus.body).deviceFound, false);
  const real = await ws(); real.send(request(400, "GetVersionInfo1"));
  assert.match((await real.next()).json.responseEntity.version, /^macOS-ft3000gm-/);
  const productionWorker = readFileSync(join(temp, "production-audit.log"), "utf8").trim().split("\n")
    .map((line) => JSON.parse(line)).find((entry) => entry.event === "server_start").pid;
  child.kill("SIGTERM"); await deadline(once(child, "exit")); assert.equal(child.exitCode, 0);
  assert.throws(() => process.kill(productionWorker, 0), { code: "ESRCH" });
  console.log("Rust TLS/HTTP/WSS, native PIN sessions, single-attempt hardware tokens, helper supervision, private Keychain IPC and crash cleanup tests PASSED");
} catch (error) {
  throw new Error(`${error.message}\nTransport diagnostics:\n${transportErrors}`, { cause: error });
} finally {
  for (const socket of sockets) socket.destroy();
  if (child && child.exitCode === null && child.signalCode === null) { child.kill("SIGTERM"); await deadline(once(child, "exit")).catch(() => child.kill("SIGKILL")); }
  rmSync(temp, { recursive: true, force: true });
}
