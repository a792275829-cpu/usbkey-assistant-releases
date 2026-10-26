import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { once } from 'node:events';
import { backend, frame, deadline, delay, waitFor } from '../tests/support/backend.mjs';
const fixture = await backend();
const request = id => ({ requestId: id, requestVersion: 1, lwsObjectId: 'transport-test', requestQuery: { function: 'GetVersionInfo1', param: {} } });
try {
  const health = await fixture.http('/health'); assert.equal(health.text, 'netca-ft3000gm'); assert.equal(health.headers['cache-control'], 'no-store');
  assert.equal((await fixture.http('/status', undefined, { Origin: 'https://example.com' })).status, 403);
  for (const path of ['/selection', '/pin-cache/clear']) {
    assert.equal((await fixture.http(path, {}, { Origin: 'null' })).status, 403);
    assert.equal((await fixture.http(path, '', { 'Content-Type': 'text/plain' })).status, 403);
  }
  assert.equal((await fixture.http('/selection', 'x'.repeat(1025))).status, 413);
  assert.equal((await fixture.http('/selection', '{')).status, 400);
  for (const options of [{ origin: 'https://example.com' }, { protocol: 'other' }, { version: '12' }, { key: 'invalid' }]) { const denied = await fixture.ws(options); assert.ok(!denied.handshake.startsWith('HTTP/1.1 101')); denied.socket.destroy(); }
  const a = await fixture.ws(); assert.match(a.handshake, /Sec-WebSocket-Protocol: crypto-jsonrpc-protocol/i);
  a.send(request(1)); const response = (await a.next()).json; assert.equal(response.requestId, 1); assert.equal(response.lwsObjectId, 'transport-test'); assert.equal(response.responseResult.status, 0);
  a.send('{'); assert.equal((await a.next()).json.responseResult.status, -11000);
  const fragmented = JSON.stringify({ ...request(2), note: '中文' });
  a.socket.write(frame(fragmented.slice(0, 20), { final: false })); a.socket.write(frame(fragmented.slice(20), { opcode: 0 })); assert.equal((await a.next()).json.requestId, 2);
  a.send('ping', { opcode: 9 }); const pong = await a.next(); assert.equal(pong.opcode, 10); assert.equal(pong.payload.toString(), 'ping');
  for (const options of [{ masked: false }, { rsv: true }, { opcode: 9 }]) {
    const bad = await fixture.ws(); bad.send(options.opcode === 9 ? 'x'.repeat(126) : '{}', options); const result = await bad.next(); assert.ok(result.closed || result.opcode === 8); bad.socket.destroy();
  }
  const oversized = await fixture.ws(); oversized.socket.write(frame(Buffer.alloc(1024 * 1024 + 1, 32))); const rejected = await oversized.next(); assert.ok(rejected.closed || rejected.opcode === 8); oversized.socket.destroy();
  const closing = await fixture.ws(); closing.socket.write(frame(Buffer.from([3, 232]), { opcode: 8 })); assert.equal((await closing.next()).opcode, 8); closing.socket.destroy();
  for (let i = 0; i < 70; i++) { const ws = await fixture.ws(); ws.send(request(100 + i)); ws.socket.destroy(); }
  await delay(500); a.send(request(300)); assert.equal((await a.next()).json.responseResult.status, 0);
  const worker = readFileSync(join(fixture.root, 'audit'), 'utf8').trim().split('\n').map(JSON.parse).find(v => v.mode === 'rust-native-worker').pid;
  const vector = JSON.parse(readFileSync('tests/fixtures/legacy-compatibility.json'));
  for (const name of ['sign', 'enc']) writeFileSync(join(fixture.root, name + '.key'), vector.certificates[name].key);
  fixture.configure(['a1'], 0, { mode: 'hang', sign: vector.certificates.sign.der, enc: vector.certificates.enc.der });
  a.send({ requestId: 301, requestQuery: { function: 'SignedDataSign', param: { algo: 4, detached: 1, certPwd: 'fixture-pin', data: { text: vector.content } } } });
  let helper;
  await waitFor(() => { const log = join(fixture.root, 'helper.jsonl'); if (!existsSync(log)) return false; helper = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse).find(v => v.op === '--sign-digest-info' && v.event === 'start'); return Boolean(helper); });
  const exit = once(fixture.child, 'exit'); process.kill(worker, 'SIGKILL'); await deadline(exit); assert.notEqual(fixture.child.exitCode, 0);
  assert.throws(() => process.kill(helper.pid, 0), { code: 'ESRCH' }, 'worker crash must terminate and reap active hardware');
  console.log('Native Rust TLS/HTTP/WSS framing, Origin checks, limits, disconnect recovery and active helper cleanup on worker failure tests PASSED');
} finally { await fixture.close(); }
