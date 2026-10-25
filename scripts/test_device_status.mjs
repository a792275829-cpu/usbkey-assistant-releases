import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDeviceSelection } from "../server/device-selection.mjs";
import { readDeviceStatus } from "../server/device-client.mjs";
const temp = mkdtempSync(join(tmpdir(), "device-status-"));
try {
  const records = [];
  for (const [file_id, usage] of [["3001", "digitalSignature"], ["3002", "keyEncipherment"]]) {
    const cert = join(temp, `${file_id}.pem`);
    execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-utf8", "-subj", `/O=测试电力企业/CN=Status ${file_id}`, "-addext", `keyUsage=${usage}`, "-days", "1",
      "-keyout", join(temp, `${file_id}.key`), "-out", cert], { stdio: "ignore" });
    const encode = execFileSync("/usr/bin/openssl", ["x509", "-in", cert, "-outform", "DER"]).toString("base64");
    records.push({ file_id, encode });
  }
  const probe = { certificate_count: 2, certificate_file_ids: "3001;3002", certificates: records };
  const dependencies = { probeReader: async () => probe, pinStatusReader: async () => ({ retries: 0 }) };
  const status = await readDeviceStatus(dependencies);
  assert.equal(status.signingCertificateFileId, "3001"); assert.equal(status.retries, 0);
  assert.equal(status.organization, "测试电力企业");
  assert.equal(status.holder, "Status 3001");
  assert.match(status.expiresAt, /^\d{4}-\d{2}-\d{2}T.*Z$/);
  const encryptionOnly = await readDeviceStatus({ ...dependencies,
    probeReader: async () => ({ ...probe, certificates: [records[1]] }) });
  assert.equal(encryptionOnly.signingCertificateFileId, null);
  assert.equal(encryptionOnly.holder, "Status 3002");
  const malformed = await readDeviceStatus({ ...dependencies,
    probeReader: async () => ({ ...probe, certificates: [{ file_id: "3001", encode: "broken" }] }) });
  assert.equal(malformed.organization, null);
  assert.equal(malformed.holder, null);
  assert.equal(malformed.expiresAt, null);
  const unavailable = await readDeviceStatus({ ...dependencies,
    pinStatusReader: async () => { throw new Error("unavailable"); } });
  assert.equal(unavailable.deviceFound, true); assert.equal(unavailable.retries, null);
  assert.equal(JSON.stringify(status).includes(records[0].encode), false);
  let revoked = 0;
  const selection = createDeviceSelection({ authentication: { invalidate: () => { revoked++; } } });
  const both = { certificate_count: 4, devices: [
    { ...probe, device_id: "a1" }, { ...probe, device_id: "b1" },
  ] };
  const multiDeps = { ...dependencies, selection, probeReader: async () => both };
  const multi = await readDeviceStatus(multiDeps);
  assert.equal(multi.deviceCount, 2); assert.equal(multi.requiresSelection, false);
  assert.equal(multi.selectedDeviceId, "a1");
  assert.equal(multi.devices.length, 2); assert.equal(multi.devices[0].holder, "Status 3001");
  assert.equal(multi.devices[1].signingCertificateFileId, "3001");
  assert.equal(JSON.stringify(multi).includes(records[0].encode), false);
  selection.choose("b1", both.devices);
  const chosen = await readDeviceStatus(multiDeps);
  assert.equal(chosen.selectedDeviceId, "b1"); assert.equal(chosen.requiresSelection, false);
  assert.equal(chosen.holder, "Status 3001"); assert.equal(chosen.signingCertificateFileId, "3001");
  assert.equal(revoked, 2);
  selection.reconcile([both.devices[0]]); assert.equal(selection.current(), "a1"); assert.equal(revoked, 3);
  assert.throws(() => selection.choose("missing", both.devices), /断开/);
  console.log("Device signing-certificate selection and status privacy tests PASSED");
} finally { rmSync(temp, { recursive: true, force: true }); }
