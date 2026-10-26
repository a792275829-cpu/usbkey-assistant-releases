import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const tool = resolve('scripts/project-tool.sh'), root = mkdtempSync(join(tmpdir(), 'usbkey-tools-'));
const run = (...args) => execFileSync('/bin/sh', [tool, ...args], { encoding: 'utf8' });
const bundle = (name, version, identifier = 'cn.gdpower.usbkeyassistant') => {
  const app = join(root, name + '.app'), dir = join(app, 'Contents/MacOS'); mkdirSync(dir, { recursive: true });
  writeFileSync(join(app, 'Contents/Info.plist'), `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleShortVersionString</key><string>${version}</string></dict></plist>`);
  writeFileSync(join(dir, 'helper with space'), '#!/bin/sh\nexit 0\n'); chmodSync(join(dir, 'helper with space'), name === 'old' ? 0o644 : 0o755);
  writeFileSync(join(dir, 'unchanged'), 'unchanged'); return app;
};
try {
  const old = bundle('old', '1.0.0'), next = bundle('new', '1.0.1');
  writeFileSync(join(old, 'Contents/MacOS/removed'), 'old'); writeFileSync(join(next, 'Contents/MacOS/new'), 'new');
  const args = ['patch', '--from', old, '--app', next, '--out', root, '--force'];
  const output = run(...args); const archive = output.match(/^PATCH=(.+)$/m)[1];
  const manifest = JSON.parse(execFileSync('/usr/bin/tar', ['-xOf', archive, 'patch.json'], { encoding: 'utf8' }));
  const files = new Map(manifest.files.map(v => [v.path, v]));
  assert.equal(files.get('Contents/MacOS/helper with space').mode, '0755'); assert.equal(files.has('Contents/MacOS/unchanged'), false);
  assert.equal(manifest.base.find(v => v.path === 'Contents/MacOS/helper with space').sha256, files.get('Contents/MacOS/helper with space').sha256);
  assert.deepEqual(manifest.remove, ['Contents/MacOS/removed']); assert.ok(files.has('Contents/MacOS/new')); assert.equal(manifest.base.some(v => v.path === 'Contents/MacOS/new'), false);
  const extracted = join(root, 'extract'); mkdirSync(extracted); execFileSync('/usr/bin/tar', ['-xzf', archive, '-C', extracted]);
  assert.match(execFileSync('/usr/bin/stat', ['-f', '%Lp', join(extracted, 'Contents/MacOS/helper with space')], { encoding: 'utf8' }), /^755/);
  const digest = createHash('sha256').update(readFileSync(archive)).digest('hex'); assert.ok(readFileSync(archive + '.sha256', 'utf8').startsWith(digest + '  '));
  assert.notEqual(spawnSync('/bin/sh', [tool, 'patch', '--from', old, '--app', old, '--out', root]).status, 0);
  const unrelated = bundle('unrelated', '0.1', 'example.unrelated'); assert.notEqual(spawnSync('/bin/sh', [tool, 'patch', '--from', unrelated, '--app', next, '--out', root]).status, 0);
  for (const version of ['1.1.9', '1.1.10', '1.1.21', '1.2.0']) writeFileSync(join(root, `USBKeyAssistant-${version}-apple-silicon.dmg`), 'fixture');
  assert.equal(run('previous-version', root, '1.1.21').trim(), '1.1.10');
  writeFileSync(join(root, '广东电力USBKey助手-1.0.1-apple-silicon.dmg'), 'tiny');
  assert.match(run(...args.filter(v => v !== '--force')), /^SKIP=/); assert.equal(existsSync(archive), false); assert.equal(existsSync(archive + '.sha256'), false);
  console.log('Swift release tools: patch modes, removal, hashes, bundle identity, size fallback and version selection tests PASSED');
} finally { rmSync(root, { recursive: true, force: true }); }
