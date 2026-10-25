import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { connect } from "node:tls";
import { get } from "node:https";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createBridgeServer } from "../server/netca_readonly_bridge.mjs";
import { createSerialQueue } from "../server/serial-queue.mjs";

const temp = mkdtempSync(join(tmpdir(), "bridge-architecture-"));
const sockets = new Set();
let server;
try {
  // A library import must succeed without certificates and without creating logs.
  const entry = pathToFileURL(join(import.meta.dirname, "../server/netca_readonly_bridge.mjs")).href;
  execFileSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(entry)})`,
    "--", "--cert", join(temp, "missing.crt"), "--key", join(temp, "missing.key"),
    "--log", join(temp, "logs/bridge.log")], { cwd: temp });
  assert.equal(existsSync(join(temp, "logs")), false);

  const queue = createSerialQueue(1);
  let release;
  const held = queue(() => new Promise((resolve) => { release = resolve; }));
  await Promise.resolve();
  await assert.rejects(queue(() => {}), /队列已满/);
  release(); await held;
  await assert.rejects(queue(() => { throw new Error("expected failure"); }), /expected failure/);
  assert.equal(await queue(() => 42), 42);

  execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-days", "1", "-keyout", join(temp, "key"), "-out", join(temp, "cert")], { stdio: "ignore" });
  const tls = { key: readFileSync(join(temp, "key")), cert: readFileSync(join(temp, "cert")) };
  let active = 0, maximum = 0, calls = 0;
  const operation = async () => {
    active += 1; maximum = Math.max(maximum, active); calls += 1;
    try { await new Promise((resolve) => setTimeout(resolve, 40)); }
    finally { active -= 1; }
  };
  server = createBridgeServer({ tls,
    dispatchRequest: async (request) => {
      await operation();
      if (request.requestId === 1) throw new Error("simulated device failure");
      return { requestId: request.requestId, responseResult: { status: 0 }, responseEntity: {} };
    },
    readStatus: async () => {
      await operation();
      return { deviceFound: true, certificateCount: 2, certificateFileId: "3001", retries: 5 };
    },
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = server.address().port;
  const options = { host: "127.0.0.1", port, ca: tls.cert, servername: "localhost" };
  function https(path, headers = {}) {
    return new Promise((resolve, reject) => {
      const request = get({ ...options, path, headers }, (response) => {
        let body = ""; response.setEncoding("utf8"); response.on("data", (chunk) => { body += chunk; });
        response.on("end", () => resolve({ status: response.statusCode, body }));
      });
      request.setTimeout(3000, () => request.destroy(new Error("HTTP timeout")));
      request.on("error", reject);
    });
  }
  function rpc(id, origin = "https://pm.gd.csg.cn") {
    return new Promise((resolve, reject) => {
      const socket = connect(options); sockets.add(socket);
      let upgraded = false, buffer = Buffer.alloc(0);
      const timer = setTimeout(() => { socket.destroy(); reject(new Error("RPC timeout")); }, 3000);
      function finish(value) { clearTimeout(timer); socket.destroy(); sockets.delete(socket); resolve(value); }
      socket.on("error", (error) => { clearTimeout(timer); reject(error); });
      socket.on("secureConnect", () => {
        const key = randomBytes(16).toString("base64");
        const headers = Buffer.from(["GET / HTTP/1.1", `Host: localhost:${port}`, "Upgrade: websocket",
          "Connection: Upgrade", `Sec-WebSocket-Key: ${key}`, "Sec-WebSocket-Version: 13",
          "Sec-WebSocket-Protocol: crypto-jsonrpc-protocol", `Origin: ${origin}`, "\r\n"].join("\r\n"));
        const payload = Buffer.from(JSON.stringify({ requestId: id }));
        const mask = randomBytes(4);
        const masked = Buffer.from(payload);
        for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
        // Exercise the HTTP upgrade head path as well as normal frame parsing.
        socket.write(Buffer.concat([headers, Buffer.from([0x81, 0x80 | payload.length]), mask, masked]));
      });
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!upgraded) {
          const end = buffer.indexOf("\r\n\r\n"); if (end < 0) return;
          const headers = buffer.subarray(0, end).toString();
          if (!headers.startsWith("HTTP/1.1 101")) { finish({ denied: headers }); return; }
          upgraded = true; buffer = buffer.subarray(end + 4);
        }
        if (buffer.length < 2) return;
        let size = buffer[1] & 127, offset = 2;
        if (size === 126) { if (buffer.length < 4) return; size = buffer.readUInt16BE(2); offset = 4; }
        if (buffer.length < offset + size) return;
        finish(JSON.parse(buffer.subarray(offset, offset + size).toString()));
      });
    });
  }
  const results = await Promise.all([rpc(1), rpc(2), https("/status")]);
  assert.notEqual(results[0].responseResult.status, 0);
  assert.equal(results[1].responseResult.status, 0);
  assert.equal(JSON.parse(results[2].body).retries, 5);
  assert.equal(maximum, 1, "different sockets and HTTP status must share one device queue");
  assert.equal(calls, 3);
  assert.equal((await https("/health")).body, "netca-ft3000gm");
  assert.equal((await https("/status", { Origin: "https://example.com" })).status, 403);
  assert.match((await rpc(3, "https://example.com")).denied, /403/);
  assert.equal(calls, 3);
  console.log("Bridge import isolation, cross-connection queue, failure recovery and status tests PASSED");
} finally {
  for (const socket of sockets) socket.destroy();
  if (server) { await new Promise((resolve) => server.close(resolve)); }
  rmSync(temp, { recursive: true, force: true });
}
