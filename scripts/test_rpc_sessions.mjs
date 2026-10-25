import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { constants, privateEncrypt, privateDecrypt } from "node:crypto";
import { dispatch, signedDataSign, envelopedDataEncrypt, envelopedDataDecrypt, success, failure } from "../server/rpc.mjs";
import { createPinSession } from "../server/pin-session.mjs";
import { certificateInventory, selectCertificate, assertPrivateKeyContainer } from "../server/certificates.mjs";
import { createDeviceSelection } from "../server/device-selection.mjs";
import { signerFailure } from "../server/device-client.mjs";

const temp = mkdtempSync(join(tmpdir(), "rpc-sessions-"));
const sessions = [];
try {
  const keys = new Map();
  const makeDevice = (id) => {
    const certificates = [];
    for (const [file_id, usage] of [["3001", "digitalSignature"], ["3002", "keyEncipherment"]]) {
      const name = join(temp, `${id}-${file_id}`);
      execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
        `/O=Test/CN=NETCA ${id}-${file_id}`, "-addext", `keyUsage=${usage}`, "-addext", "subjectKeyIdentifier=hash",
        "-days", "1", "-keyout", `${name}.key`, "-out", `${name}.pem`], { stdio: "ignore" });
      const encode = execFileSync("/usr/bin/openssl", ["x509", "-in", `${name}.pem`, "-outform", "DER"]).toString("base64");
      certificates.push({ file_id, encode }); keys.set(`${id}-${file_id}`, readFileSync(`${name}.key`));
    }
    return { device_found: true, device_id: id, device_sn: `sn-${id}`, device_type: 47,
      certificate_count: 2, certificates, container_diagnostics: "0:1240010101300109023002" };
  };
  const a = makeDevice("a1"), b = makeDevice("b1");
  let current = a, prompts = 0, signed = 0, decrypts = 0, clock = 0;
  const authentication = createPinSession({ now: () => clock, prompt: async () => { prompts++; return "test-pin"; } });
  sessions.push(authentication);
  const signer = async (pin, digest, record) => {
    signed++; assert.equal(pin, "test-pin");
    return privateEncrypt({ key: keys.get(`${record.deviceId}-3001`), padding: constants.RSA_PKCS1_PADDING }, digest);
  };
  const deps = { authentication, probeReader: async () => current, signer };
  const param = { algo: 4, detached: 1, data: { text: Buffer.from("challenge").toString("base64") },
    cert: { encode: "", type: "device", condition: "CertType='Signature'" } };
  const request = (name, param = {}) => ({ requestVersion: 1, requestId: 7, lwsObjectId: "connection-a",
    requestQuery: { function: name, param } });
  const initial = await dispatch(request("SignedDataSign", { ...param, certPwd: "test-pin" }), deps);
  assert.equal(initial.responseVersion, 1); assert.equal(initial.lwsObjectId, "connection-a");
  assert.ok(initial.responseEntity.signValue); assert.equal(prompts, 0);
  await dispatch(request("ClearPwdCache"), deps);
  assert.equal(authentication.hasAuthenticatedSessionPin(), true);
  const second = await signedDataSign(param, deps);
  assert.equal(second.signCert, a.certificates[0].encode); assert.equal(prompts, 0);
  const clear = Buffer.from("shared signing and encryption lease");
  const encryptionParam = { data: { text: clear.toString("base64") }, cert: { type: "device", condition: "CertType='Encrypt'" } };
  for (const algo of [undefined, null, -2, -1, 0, 4, 6]) {
    const enc = await envelopedDataEncrypt({ ...encryptionParam, algo }, async () => a);
    const dec = await envelopedDataDecrypt({ encData: enc.encryptValue }, { ...deps,
      decryptBlockWithoutPin: async () => { throw new Error("must reuse PIN lease"); },
      decryptBlockWithPin: async (pin, bytes) => {
        assert.equal(pin, "test-pin"); decrypts++;
        return privateDecrypt({ key: keys.get("a1-3002"), padding: constants.RSA_NO_PADDING }, bytes);
      } });
    assert.deepEqual(Buffer.from(dec.clearValue, "base64"), clear);
    assert.equal(dec.algo, algo === 6 ? 6 : 4);
    assert.equal(dec.certObject.Thumbprint256.length, 64);
  }
  assert.equal(prompts, 0); assert.equal(decrypts, 7);
  const list = (await dispatch(request("GetCertList"), deps)).responseEntity;
  assert.equal(list.deviceCount, 1); assert.equal(list.certCount, 2); assert.equal(list.certInfo.length, 2);
  assert.deepEqual(list.certInfo.map((r) => r.keyUsage), [1, 4]);
  assert.equal((await dispatch(request("GetCertList", { type: 1 }), deps)).responseEntity.certInfo[0].fileId, "3002");
  assert.equal((await dispatch(request("GetCertList", { type: 2 }), deps)).responseEntity.certInfo[0].fileId, "3001");
  assert.equal((await dispatch(request("GetCertList", { type: 2 }), { ...deps,
    now: () => Date.now() + 2 * 24 * 60 * 60_000 })).responseEntity.certCount, 0,
    "type=2 must exclude signing certificates outside their validity period");
  const attr = await dispatch(request("GetCertStringAttribute", { id: -1 }), deps);
  assert.equal(attr.responseEntity.certCode, a.certificates[0].encode);
  // Real portal netcapki.js uses JSON-in-type plus && boolean conditions.
  const portalSelector = {
    type: '{"UIFlag":"default", "InValidity":true,"Type":"signature" , "Method":"device", "Value":"any"}',
    condition: "InValidity='True'&&CertType='Signature'&&CheckPrivKey='True'",
  };
  const privateCounts = [prompts, signed, decrypts];
  const portalCert = await dispatch(request("GetCertStringAttribute", { id: -1, cert: portalSelector }), deps);
  assert.equal(portalCert.responseEntity.certCode, a.certificates[0].encode);
  const actualPortalSelector = JSON.parse(readFileSync(new URL('../tests/fixtures/portal-certificate-selector.json', import.meta.url)));
  assert.equal(actualPortalSelector.type.length, 91); assert.equal(actualPortalSelector.condition.length, 61);
  const actualPortalCert = await dispatch(request("GetCertStringAttribute", { id: -1, cert: { encode: null, ...actualPortalSelector } }), deps);
  assert.equal(actualPortalCert.responseEntity.certCode, a.certificates[0].encode);
  assert.equal(selectCertificate({ devices: [a, b] }, actualPortalSelector, undefined, undefined, "b1").deviceId, "b1");
  assert.throws(() => selectCertificate(a, { ...actualPortalSelector, condition: "IssuerCN~'OtherCA' && InValidity='True' && CertType='Signature'" }), /未找到/,
    "issuer constraint must not be dropped during compatibility parsing");
  assert.throws(() => selectCertificate(a, { ...actualPortalSelector, condition: "IssuerCN='NETCA'" }), /未找到/,
    "issuer equality must remain distinct from substring matching");
  assert.throws(() => selectCertificate(a, { ...actualPortalSelector, condition: "CertType~'Sign'" }), /筛选条件/);
  assert.throws(() => selectCertificate(a, { ...actualPortalSelector, condition: "IssuerCN~'NETCA' || CertType='Signature'" }), /筛选条件/);
  assert.throws(() => selectCertificate(a, { ...actualPortalSelector, type: actualPortalSelector.type + ';process.exit()' }), /设备证书选择/);
  assert.deepEqual([prompts, signed, decrypts], privateCounts, "selection must never authenticate or sign");
  assert.equal(selectCertificate({ devices: [a, b] }, portalSelector, undefined, undefined, "b1").deviceId, "b1");
  assert.throws(() => selectCertificate(a, { ...portalSelector, type: '{"Method":"store","Value":"any"}' }), /选择规则/);
  assert.throws(() => selectCertificate(a, { ...portalSelector, type: '{' }), /设备证书选择/);
  assert.throws(() => selectCertificate(a, { ...portalSelector, condition: "InValidity='maybe'" }), /布尔/);
  assert.throws(() => selectCertificate(a, { ...portalSelector, condition: "CheckPrivKey='True'&&" }), /不完整/);
  assert.throws(() => selectCertificate({ ...a, device_id: "" }, portalSelector), /未找到/);
  const falseValidity = { ...portalSelector, condition: "InValidity='False'" };
  assert.throws(() => selectCertificate(a, falseValidity), /未找到/);
  assert.equal(success({}, {}).responseVersion, 1); assert.equal(failure({}, "fail").responseVersion, 1);

  // Unsupported or ambiguous selection must stop before any private operation.
  const before = signed;
  await assert.rejects(signedDataSign({ ...param, cert: { condition: "CertType='Signature' OR DeviceType=47" } }, deps), /筛选条件/);
  await assert.rejects(signedDataSign({ ...param, cert: { condition: "BadField='x'" } }, deps), /筛选条件/);
  current = { devices: [a, b] };
  await assert.rejects(signedDataSign(param, deps), /多张证书/);
  assert.equal(signed, before);
  await signedDataSign({ ...param, cert: { condition: "CertType='Signature' AND DeviceSn='sn-b1'" } }, deps);
  assert.equal(prompts, 1, "a different token must prompt instead of reusing token A's PIN");
  assert.equal(selectCertificate(current, { deviceId: "a1", encode: a.certificates[0].encode }, "Sign").deviceId, "a1");
  assert.throws(() => selectCertificate(current, { deviceId: "a1", encode: b.certificates[0].encode }, "Sign"), /未找到/);
  assert.throws(() => assertPrivateKeyContainer({ ...certificateInventory(a).records[0], fileId: "3009" }, "Sign"), /容器/);

  const preferenceAuth = createPinSession({ prompt: async () => "test-pin" }); sessions.push(preferenceAuth);
  const preference = createDeviceSelection({ authentication: preferenceAuth });
  preference.choose("a1", current.devices);
  const preferred = await signedDataSign(param, { ...deps, authentication: preferenceAuth, selection: preference });
  assert.equal(preferred.signCert, a.certificates[0].encode);
  const explicitOther = await signedDataSign({ ...param, cert: { encode: b.certificates[0].encode } },
    { ...deps, authentication: preferenceAuth, selection: preference });
  assert.equal(explicitOther.signCert, b.certificates[0].encode, "explicit certificate must override only the ambiguous default");
  preference.reconcile([]);
  // PIN rejection yields a business failure, clears both caches, and never retries.
  current = b;
  let failedAttempts = 0;
  const error = signerFailure({ pin_verified: false, verify_sw: "63C2", retries: 2 }, false, "--sign-digest-info");
  const failed = await dispatch(request("SignedDataSign", { ...param, certPwd: "wrong-test" }), {
    ...deps, signer: async () => { failedAttempts++; throw error; } });
  assert.equal(failed.responseResult.status, 0);
  assert.deepEqual(failed.responseEntity, { result: -5, retrynum: 2 });
  assert.equal(failedAttempts, 1); assert.equal(authentication.hasAuthenticatedSessionPin(), false);
  assert.equal(signerFailure({ pin_verified: false, verify_sw: "6983", retries: 0 }).netcaResult, -81);
  assert.equal(signerFailure({ pin_verified: false, verify_sw: "6F00", retries: -1 }).code, undefined);
  await signedDataSign(param, deps); assert.equal(prompts, 2);
  await assert.rejects(signedDataSign(param, { ...deps, signer: async () => Buffer.alloc(256) }), /公钥自检/);
  assert.equal(authentication.hasAuthenticatedSessionPin(), false);
  await signedDataSign(param, deps); assert.equal(prompts, 3);
  clock += 5 * 60_000 + 1;
  await signedDataSign(param, deps); assert.equal(prompts, 4, "expired lease prompts once");
  authentication.reconcileDevices([]);
  assert.equal(authentication.hasAuthenticatedSessionPin(), false);
  await signedDataSign(param, deps); assert.equal(prompts, 5);
  // Same token ID but changed certificate set invalidates the lease.
  current = { ...b, certificates: [a.certificates[0], b.certificates[1]] };
  await signedDataSign(param, { ...deps, signer: async (pin, digest) => {
    assert.equal(pin, "test-pin"); return privateEncrypt({ key: keys.get("a1-3001"), padding: constants.RSA_PKCS1_PADDING }, digest);
  } });
  assert.equal(prompts, 6);

  const empty = await dispatch(request("GetCertList"), { ...deps, probeReader: async () => ({ devices: [] }) });
  assert.equal(empty.responseEntity.certCount, 0); assert.equal(empty.responseEntity.deviceCount, 0);
  // A malformed request cannot consume a PIN attempt or establish a lease.
  const calls = signed;
  await assert.rejects(signedDataSign({ ...param, includeCertOption: 9 }, deps), /包含选项/);
  assert.equal(signed, calls);

  // A rejected cached PIN is one attempt, not a second dialog/retry.
  let cachedPrompts = 0, cachedAttempts = 0;
  const cachedSession = createPinSession({ prompt: async () => { cachedPrompts++; return "test-pin"; } });
  sessions.push(cachedSession);
  const binding = certificateInventory(b).records[0].binding;
  await cachedSession.withAuthentication(binding, "test-pin", async () => true);
  const rejectedCached = await dispatch(request("SignedDataSign", param), { ...deps,
    authentication: cachedSession, probeReader: async () => b,
    signer: async () => { cachedAttempts++; throw error; } });
  assert.equal(rejectedCached.responseEntity.retrynum, 2);
  assert.equal(cachedAttempts, 1); assert.equal(cachedPrompts, 0);
  assert.equal(cachedSession.hasAuthenticatedSessionPin(), false);

  await cachedSession.withAuthentication(binding, "test-pin", async () => true);
  await assert.rejects(signedDataSign(param, { ...deps, authentication: cachedSession,
    probeReader: async () => { throw new Error("probe unavailable"); } }), /probe unavailable/);
  assert.equal(cachedSession.hasAuthenticatedSessionPin(), false, "probe failure revokes old credentials");

  // Invalidating while a dialog is pending prevents its stale result being used.
  let resolvePrompt;
  const stale = createPinSession({ prompt: () => new Promise((resolve) => { resolvePrompt = resolve; }) }); sessions.push(stale);
  let operated = false;
  const pending = stale.withAuthentication("old-token:certs", undefined, async () => { operated = true; });
  await Promise.resolve(); stale.invalidate(); resolvePrompt("test-pin");
  await assert.rejects(pending, /状态已改变/); assert.equal(operated, false);
  console.log("RPC certificate selection, bound shared PIN leases, error contracts and invalidation tests PASSED");
} finally {
  sessions.forEach((s) => s.invalidate()); rmSync(temp, { recursive: true, force: true });
}
