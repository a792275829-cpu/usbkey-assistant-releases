import assert from 'node:assert/strict';
import { backend, waitFor, delay } from '../tests/support/backend.mjs';
let fixture = await backend();
try {
  fixture.configure(['a1'], 4.5);
  const results = await Promise.all([1, 2, 3].map(() => fixture.http('/status')));
  assert.ok(results.every(v => v.status === 503)); assert.equal(fixture.events('start'), 1);
  await waitFor(() => fixture.events('done') === 1); await delay(200);
  const result = await fixture.http('/status'); assert.equal(result.status, 200); assert.equal(result.json().deviceFound, true); assert.equal(result.json().stale, true); assert.equal(result.json().selectedDeviceId, 'a1');
} finally { await fixture.close(); }
fixture = await backend();
try {
  fixture.configure(['a1', 'b1'], 8);
  const scan = fixture.http('/status'); await waitFor(() => fixture.events('start') === 1);
  const select = fixture.http('/selection', { deviceId: 'b1' }), clear = fixture.http('/pin-cache/clear', {});
  assert.deepEqual((await Promise.all([scan, select, clear])).map(v => v.status), [503, 503, 503]);
  await waitFor(() => fixture.events('done') === 2); fixture.configure(['a1', 'b1']);
  assert.equal((await fixture.http('/pin-cache/clear', {})).status, 200); assert.equal(fixture.clears, 1);
  assert.equal((await fixture.http('/status')).json().selectedDeviceId, 'a1');
} finally { await fixture.close(); }
fixture = await backend();
try {
  fixture.clearDelay = 11000; const started = Date.now();
  const result = await fixture.http('/pin-cache/clear', {});
  assert.equal(result.status, 200); assert.equal(result.json().cleared, true); assert.ok(Date.now() - started >= 10000); assert.equal(fixture.clears, 1);
} finally { await fixture.close(); }
console.log('Rust control deadlines, late cache publication, scan sharing and Keychain completion tests PASSED');
