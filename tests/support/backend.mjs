// Offline fixture: real Rust transport/worker, simulated hardware and Keychain.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync, rmSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { request } from 'node:https';
import { connect } from 'node:tls';
import { randomBytes } from 'node:crypto';
export const delay = ms => new Promise(r => setTimeout(r, ms));
export async function deadline(p, ms = 25000) {
  let timer; try { return await Promise.race([p, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('fixture timeout')), ms); })]); } finally { clearTimeout(timer); }
}
export async function waitFor(predicate, ms = 20000) { const until = Date.now() + ms; while (!predicate()) { assert.ok(Date.now() < until, 'fixture did not reach expected state'); await delay(50); } }
export function frame(value, { final = true, opcode = 1, masked = true, rsv = false } = {}) {
  const data = Buffer.from(value), mask = randomBytes(4), first = (final ? 128 : 0) | (rsv ? 64 : 0) | opcode;
  let header;
  if (data.length < 126) header = Buffer.from([first, (masked ? 128 : 0) | data.length]);
  else if (data.length < 65536) { header = Buffer.alloc(4); header[0] = first; header[1] = (masked ? 128 : 0) | 126; header.writeUInt16BE(data.length, 2); }
  else { header = Buffer.alloc(10); header[0] = first; header[1] = (masked ? 128 : 0) | 127; header.writeBigUInt64BE(BigInt(data.length), 2); }
  if (masked) for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
  return Buffer.concat(masked ? [header, mask, data] : [header, data]);
}
export async function backend() {
  const root = mkdtempSync(join(tmpdir(), 'usbkey-backend-')), bin = resolve(process.env.RUST_BIN_DIR ?? 'rust-transport/target/debug');
  let child, clearDelay = 0, clears = 0, stderr = '', buffer = ''; const sockets = new Set();
  const configure = (devices, delay = 0, extra = {}) => { writeFileSync(join(root, 'state.tmp'), JSON.stringify({ devices, delay, ...extra })); renameSync(join(root, 'state.tmp'), join(root, 'state.json')); };
  configure(['a1']); copyFileSync(resolve('build/test-device-helper'), join(root, 'helper'));
  try {
    execFileSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-days', '1', '-keyout', join(root, 'key'), '-out', join(root, 'cert')], { stdio: 'ignore' });
    child = spawn(join(bin, 'usbkey-transport'), ['--native-worker', join(bin, 'usbkey-worker'), '--port', '0', '--cert', join(root, 'cert'), '--key', join(root, 'key'), '--probe', join(root, 'helper'), '--signer', join(root, 'helper'), '--log', join(root, 'audit')], { env: { ...process.env, USBKEY_PRIVATE_PIN_CHANNEL: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.on('error', () => {});
    child.stdout.setEncoding('utf8'); child.stdout.on('data', data => {
      buffer += data;
      while (buffer.includes('\n')) {
        const end = buffer.indexOf('\n'), input = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        assert.equal(input.privateChannel, 'pin-store-v1');
        const wait = input.operation === 'clear' ? clearDelay : 0; if (input.operation === 'clear') clears++;
        const timer = setTimeout(() => { if (!child.stdin.destroyed) child.stdin.write(JSON.stringify({ privateChannel: 'pin-store-v1', requestId: input.requestId, status: 0 }) + '\n'); }, wait); timer.unref();
      }
    });
    const port = await deadline(new Promise((resolve, reject) => {
      child.stderr.on('data', data => { stderr += data; const match = stderr.match(/listening on 127\.0\.0\.1:(\d+)/); if (match) resolve(Number(match[1])); });
      child.once('error', reject); child.once('exit', code => reject(new Error(`backend exited ${code}: ${stderr}`)));
    }));
    const tls = { host: '127.0.0.1', port, ca: readFileSync(join(root, 'cert')), servername: 'localhost' };
    function http(path, body, headers = {}, method = body === undefined ? 'GET' : 'POST') {
      return deadline(new Promise((resolve, reject) => {
        const req = request({ ...tls, path, method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers } }, res => {
          let text = ''; res.on('data', c => text += c); res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers, json: () => JSON.parse(text) }));
        }); req.on('error', reject); req.end(body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body));
      }));
    }
    async function ws({ origin = 'https://pm.gd.csg.cn', protocol = 'crypto-jsonrpc-protocol', version = '13', key = randomBytes(16).toString('base64') } = {}) {
      const socket = connect(tls); sockets.add(socket); socket.on('error', () => {}); await deadline(once(socket, 'secureConnect'));
      let buffer = Buffer.alloc(0), upgraded = false; const received = [], waiting = [];
      const deliver = v => waiting.length ? waiting.shift()(v) : received.push(v);
      const next = () => deadline(received.length ? Promise.resolve(received.shift()) : new Promise(r => waiting.push(r)));
      socket.once('close', () => { sockets.delete(socket); deliver({ closed: true }); });
      socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!upgraded) { const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return; deliver({ handshake: buffer.subarray(0, end).toString() }); buffer = buffer.subarray(end + 4); upgraded = true; }
        while (buffer.length >= 2) {
          let size = buffer[1] & 127, offset = 2;
          if (size === 126) { if (buffer.length < 4) return; size = buffer.readUInt16BE(2); offset = 4; }
          else if (size === 127) { if (buffer.length < 10) return; size = Number(buffer.readBigUInt64BE(2)); offset = 10; }
          if (buffer.length < offset + size) return;
          const opcode = buffer[0] & 15, payload = buffer.subarray(offset, offset + size); buffer = buffer.subarray(offset + size);
          deliver({ opcode, payload, ...(opcode === 1 ? { json: JSON.parse(payload) } : {}) });
        }
      });
      socket.write(['GET / HTTP/1.1', `Host: localhost:${port}`, 'Connection: Upgrade', 'Upgrade: websocket', `Sec-WebSocket-Key: ${key}`, `Sec-WebSocket-Version: ${version}`, `Sec-WebSocket-Protocol: ${protocol}`, `Origin: ${origin}`, '\r\n'].join('\r\n'));
      const hello = await next(); return { socket, next, handshake: hello.handshake, send: (value, options) => socket.write(frame(typeof value === 'string' ? value : JSON.stringify(value), options)) };
    }
    return { root, child, configure, http, ws, get clears() { return clears; }, set clearDelay(value) { clearDelay = value; },
      events: event => { try { return readFileSync(join(root, 'helper.jsonl'), 'utf8').trim().split('\n').map(JSON.parse).filter(v => v.operation === '--include-certificate' && v.event === event).length; } catch { return 0; } },
      async close() { for (const socket of sockets) socket.destroy(); if (child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await deadline(once(child, 'exit'), 5000).catch(() => child.kill('SIGKILL')); } rmSync(root, { recursive: true, force: true }); }
    };
  } catch (error) { child?.kill('SIGKILL'); rmSync(root, { recursive: true, force: true }); throw error; }
}
