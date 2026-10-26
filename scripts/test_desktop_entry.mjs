// Temporary bundles only; never modifies the user's Desktop or Applications.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, lstatSync, realpathSync, symlinkSync, rmSync, readdirSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
const helper = resolve('packaging/pkg-scripts/sync-desktop-entry.sh'), id = 'cn.gdpower.usbkeyassistant';
function bundle(path, version, identifier = id) { mkdirSync(join(path, 'Contents'), { recursive: true }); writeFileSync(join(path, 'Contents/Info.plist'), `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleShortVersionString</key><string>${version}</string></dict></plist>`); }
for (const kind of ['migration', 'absent', 'unrelated-app', 'unrelated-link', 'file', 'invalid']) {
  const root = mkdtempSync(join(tmpdir(), 'usbkey-desktop-test-')), source = join(root, 'Applications/USBKey Assistant.app'), desktop = join(root, 'User Home/Desktop/USBKey Assistant.app');
  const migrate = () => spawnSync('/bin/sh', [helper, source, desktop], { encoding: 'utf8' });
  try {
    mkdirSync(dirname(desktop), { recursive: true }); bundle(source, '1.1.17');
    if (kind === 'migration') {
      bundle(desktop, '1.1.16'); writeFileSync(join(desktop, 'Contents/original-data'), 'old');
      assert.equal(migrate().status, 0); assert.equal(lstatSync(desktop).isSymbolicLink(), true); assert.equal(realpathSync(desktop), realpathSync(source)); assert.equal(existsSync(join(desktop, 'Contents/original-data')), false);
      assert.equal(readdirSync(dirname(desktop)).some(v => v.startsWith('.usbkey-replace.')), false);
      bundle(source, '1.1.18'); assert.equal(execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleShortVersionString', join(desktop, 'Contents/Info.plist')], { encoding: 'utf8' }).trim(), '1.1.18'); assert.equal(migrate().status, 0);
    } else if (kind === 'absent') { assert.equal(migrate().status, 0); assert.equal(existsSync(desktop), false); }
    else if (kind === 'unrelated-app') { bundle(desktop, '1.0', 'example.unrelated'); const original = readFileSync(join(desktop, 'Contents/Info.plist')); assert.equal(migrate().status, 0); assert.deepEqual(readFileSync(join(desktop, 'Contents/Info.plist')), original); }
    else if (kind === 'unrelated-link') { const other = join(root, 'Other.app'); bundle(other, '1.0'); symlinkSync(other, desktop); assert.equal(migrate().status, 0); assert.equal(realpathSync(desktop), realpathSync(other)); }
    else if (kind === 'file') { writeFileSync(desktop, 'unrelated'); assert.equal(migrate().status, 0); assert.equal(readFileSync(desktop, 'utf8'), 'unrelated'); }
    else { bundle(desktop, '1.1.16'); bundle(source, '1.0', 'example.unrelated'); assert.notEqual(migrate().status, 0); assert.equal(lstatSync(desktop).isSymbolicLink(), false); }
    assert.equal(existsSync(join(root, 'User Home/Library/Application Support/App Backups')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
}
console.log('Desktop migration, future updates and unrelated entry preservation tests PASSED');
