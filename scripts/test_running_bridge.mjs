import { createHash, randomBytes } from "node:crypto";
import { connect } from "node:tls";

function clientTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const mask = randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x81, 0x80 | payload.length]);
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    throw new Error("Test payload is too large");
  }
  const masked = Buffer.alloc(payload.length);
  for (let index = 0; index < payload.length; index += 1) {
    masked[index] = payload[index] ^ mask[index % 4];
  }
  return Buffer.concat([header, mask, masked]);
}

function readServerFrame(buffer) {
  if (buffer.length < 2) return null;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buffer.length < 10) return null;
    length = Number(buffer.readBigUInt64BE(2));
    offset = 10;
  }
  if (buffer.length < offset + length) return null;
  return buffer.subarray(offset, offset + length).toString("utf8");
}

const request = {
  requestVersion: 1,
  requestOrigin: "macos-adapter-running-test",
  requestId: 9911,
  requestQuery: {
    function: "EnvelopedDataEncrypt",
    param: {
      cert: { encode: "", type: "device", condition: "CertType='Encrypt'" },
      algo: 0,
      data: {
        text: Buffer.from("running-bridge-test", "utf8").toString("base64"),
      },
    },
  },
};

await new Promise((resolvePromise, rejectPromise) => {
  const socket = connect({
    host: "127.0.0.1",
    port: 10443,
    servername: "localhost",
    rejectUnauthorized: true,
  });
  let handshakeComplete = false;
  let buffered = Buffer.alloc(0);
  const timeout = setTimeout(() => {
    socket.destroy();
    rejectPromise(new Error("Running bridge test timed out"));
  }, 10000);

  socket.on("secureConnect", () => {
    const key = randomBytes(16).toString("base64");
    socket.write([
      "GET / HTTP/1.1",
      "Host: 127.0.0.1:10443",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      "Sec-WebSocket-Protocol: crypto-jsonrpc-protocol",
      "Origin: https://pm.gd.csg.cn",
      "\r\n",
    ].join("\r\n"));
  });
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    if (!handshakeComplete) {
      const end = buffered.indexOf("\r\n\r\n");
      if (end === -1) return;
      const headers = buffered.subarray(0, end).toString("ascii");
      if (!headers.startsWith("HTTP/1.1 101")) {
        rejectPromise(new Error(`WebSocket upgrade failed: ${headers}`));
        socket.destroy();
        return;
      }
      handshakeComplete = true;
      buffered = buffered.subarray(end + 4);
      socket.write(clientTextFrame(JSON.stringify(request)));
    }
    const message = readServerFrame(buffered);
    if (message === null) return;
    const response = JSON.parse(message);
    if (response.responseResult?.status !== 0) {
      rejectPromise(new Error(response.responseResult?.msg ?? "Bridge failed"));
      socket.destroy();
      return;
    }
    const encoded = response.responseEntity?.encryptValue;
    if (response.responseEntity?.encryptValueType !== "base64" ||
        encoded !== response.responseEntity?.encData) {
      rejectPromise(new Error("Bridge returned incompatible encryptValue fields"));
      socket.destroy();
      return;
    }
    const cms = Buffer.from(encoded ?? "", "base64");
    if (cms.length < 100 || cms[0] !== 0x30) {
      rejectPromise(new Error("Bridge returned invalid CMS"));
      socket.destroy();
      return;
    }
    clearTimeout(timeout);
    console.log(JSON.stringify({
      status: response.responseResult.status,
      requestId: response.requestId,
      cmsBytes: cms.length,
      cmsSha256: createHash("sha256").update(cms).digest("hex"),
    }));
    socket.end();
    resolvePromise();
  });
  socket.on("error", (error) => {
    clearTimeout(timeout);
    rejectPromise(error);
  });
});
