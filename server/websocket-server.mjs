import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { audit, certificatePath, privateKeyPath, allowedOrigins, websocketProtocol, bridgeVersion } from "./runtime.mjs";
import { failure, dispatch } from "./rpc.mjs";
import { deviceSelection } from "./device-selection.mjs";
import { createDeviceMonitor } from "./device-monitor.mjs";
import { readDeviceInventory, readDeviceStatus } from "./device-client.mjs";
import { createSerialQueue } from "./serial-queue.mjs";
import { pinSession } from "./pin-session.mjs";

function encodeTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x81, payload.length]);
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

function encodeControlFrame(opcode, payload = Buffer.alloc(0)) {
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

function attachWebSocket(socket, enqueue, dispatchRequest, monitor, selection) {
  const connection = { closed: false, send(response) {
    if (connection.closed || socket.destroyed || socket.writableEnded) return;
    if (socket.writableLength > 1024 * 1024) { socket.destroy(); return; }
    socket.write(encodeTextFrame(JSON.stringify(response)));
  } };
  const cleanup = () => { connection.closed = true; monitor?.unsubscribe(connection); };
  socket.on("close", cleanup);
  socket.on("end", cleanup);
  socket.on("error", cleanup);

  let buffered = Buffer.alloc(0);
  let processing = Promise.resolve();
  let pending = 0;

  socket.on("error", () => {});
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 2) {
      const first = buffered[0];
      const second = buffered[1];
      const final = (first & 0x80) !== 0;
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      let payloadLength = second & 0x7f;
      let offset = 2;

      if (payloadLength === 126) {
        if (buffered.length < 4) return;
        payloadLength = buffered.readUInt16BE(2);
        offset = 4;
      } else if (payloadLength === 127) {
        if (buffered.length < 10) return;
        const wideLength = buffered.readBigUInt64BE(2);
        if (wideLength > 1024n * 1024n) {
          socket.destroy();
          return;
        }
        payloadLength = Number(wideLength);
        offset = 10;
      }

      if (!masked || !final || payloadLength > 1024 * 1024) {
        socket.destroy();
        return;
      }
      if (buffered.length < offset + 4 + payloadLength) return;

      const mask = buffered.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.from(buffered.subarray(offset, offset + payloadLength));
      buffered = buffered.subarray(offset + payloadLength);
      for (let i = 0; i < payload.length; i += 1) {
        payload[i] ^= mask[i % 4];
      }

      if (opcode === 0x8) {
        cleanup();
        socket.end(encodeControlFrame(0x8));
        return;
      }
      if (opcode === 0x9) {
        socket.write(encodeControlFrame(0xA, payload));
        continue;
      }
      if (opcode !== 0x1) {
        socket.destroy();
        return;
      }

      if (++pending > 64) { socket.destroy(); return; }
      processing = processing.then(async () => {
        if (connection.closed || socket.destroyed) { pending -= 1; return; }
        let request;
        let response;
        try {
          request = JSON.parse(payload.toString("utf8"));
          response = await enqueue(() => {
            if (connection.closed || socket.destroyed) throw new Error("连接已关闭");
            return dispatchRequest(request, { monitor, connection, selection });
          });
        } catch (error) {
          audit("rpc_error", {
            requestId: request?.requestId,
            method: String(request?.requestQuery?.function),
            errorType: error instanceof Error ? error.name : typeof error,
          });
          response = failure(request, error instanceof Error ? error.message : String(error));
        }
        audit("rpc_response", {
          requestId: response.requestId,
          method: String(request?.requestQuery?.function),
          status: response.responseResult.status,
        });
        connection.send(response);
        pending -= 1;
      }).catch(() => socket.destroy());
    }
  });
}


function createBridgeServer({ dispatchRequest = dispatch, readStatus = readDeviceStatus,
  readInventory = readDeviceInventory, deviceMonitor, selection = deviceSelection, authentication = pinSession,
  tls = { cert: readFileSync(certificatePath), key: readFileSync(privateKeyPath) } } = {}) {
  const enqueue = createSerialQueue();
  const monitor = deviceMonitor ?? (dispatchRequest === dispatch ? createDeviceMonitor({ readInventory, enqueue, onInventory: (devices) => selection.reconcile(devices) }) : null);
  const server = createServer({
    ...tls,
  });

  server.on("request", (request, response) => {
    if (request.method === "POST" && request.url === "/pin-cache/clear") {
      if (request.headers.origin !== undefined ||
          !/^application\/json(?:;.*)?$/i.test(request.headers["content-type"] ?? "")) {
        response.writeHead(403); response.end(); return;
      }
      request.resume();
      enqueue(async () => {
        try {
          await authentication.forgetSavedPins();
          audit("pin_store_cleared", {});
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({ cleared: true }));
        } catch {
          response.writeHead(503); response.end();
        }
      }).catch(() => { if (!response.destroyed) { response.writeHead(503); response.end(); } });
      return;
    }
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "text/plain", "cache-control": "no-store" });
      response.end("netca-ft3000gm"); return;
    }
    if (request.method === "POST" && request.url === "/selection") {
      if (request.headers.origin !== undefined ||
          !/^application\/json(?:;.*)?$/i.test(request.headers["content-type"] ?? "")) {
        response.writeHead(403); response.end(); return;
      }
      let body = "";
      request.setTimeout(5000, () => request.destroy());
      request.on("data", (chunk) => {
        if (body === null) return;
        body += chunk;
        if (Buffer.byteLength(body) > 1024) { body = null; response.writeHead(413); response.end(); }
      });
      request.on("end", () => {
        if (body === null) return;
        enqueue(async () => {
          if (response.destroyed) return;
          try {
            const { deviceId } = JSON.parse(body);
            const devices = await readInventory();
            const selectedDeviceId = selection.choose(deviceId, devices);
            response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
            response.end(JSON.stringify({ selectedDeviceId }));
          } catch {
            response.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
            response.end(JSON.stringify({ error: "所选设备不可用，请刷新设备列表" }));
          }
        }).catch(() => { if (!response.destroyed) { response.writeHead(503); response.end(); } });
      });
      return;
    }
    if (request.method === "GET" && request.url === "/status") {
      if (request.headers.origin !== undefined) {
        response.writeHead(403); response.end(); return;
      }
      enqueue(async () => {
        if (response.destroyed) return;
        try {
          const status = await readStatus({ selection });
          response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({ service: "netca-ft3000gm", version: bridgeVersion, ...status }));
        } catch {
          response.writeHead(503, { "content-type": "application/json" });
          response.end(JSON.stringify({ service: "netca-ft3000gm", deviceFound: false }));
        }
      }).catch(() => { if (!response.destroyed) { response.writeHead(503); response.end(); } });
      return;
    }
    audit("https_request", { method: request.method, path: request.url });
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end("NETCA macOS FT3000GM bridge\n");
  });

  server.on("upgrade", (request, socket, head) => {
    const origin = request.headers.origin;
    const protocols = String(request.headers["sec-websocket-protocol"] ?? "")
      .split(",")
      .map((value) => value.trim());
    const websocketKey = request.headers["sec-websocket-key"];
    audit("websocket_upgrade", {
      origin: String(origin),
      protocols,
    });

    if (!allowedOrigins.has(origin) || !protocols.includes(websocketProtocol) ||
        typeof websocketKey !== "string") {
      socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }

    const accept = createHash("sha1")
      .update(websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      .digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${accept}`,
      `Sec-WebSocket-Protocol: ${websocketProtocol}`,
      "\r\n",
    ].join("\r\n"));
    attachWebSocket(socket, enqueue, dispatchRequest, monitor, selection);
    if (head.length) socket.emit("data", head);
  });


  server.on("listening", () => monitor?.start());
  server.on("close", () => monitor?.dispose());
  return server;
}
export { createBridgeServer };
