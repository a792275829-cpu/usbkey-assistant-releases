import { execFileSync } from "node:child_process";
import { strict as assert } from "node:assert";
import { createPrivateKey, sign, X509Certificate } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildCertificatePath,
  buildDetachedCms,
  buildNetcaLegacyDetachedCms,
  buildSignedAttributes,
  envelopedDataEncrypt,
  subjectKeyIdentifier,
} from "../server/netca_readonly_bridge.mjs";

const workDirectory = mkdtempSync(join(tmpdir(), "gdpower-envelope-test-"));
const keyPath = join(workDirectory, "recipient.key");
const certificatePath = join(workDirectory, "recipient.crt");
const certificateDerPath = join(workDirectory, "recipient.der");
const envelopePath = join(workDirectory, "envelope.der");
const decryptedPath = join(workDirectory, "decrypted.bin");
const signedContentPath = join(workDirectory, "signed-content.bin");
const verifiedContentPath = join(workDirectory, "verified-content.bin");
const clearText = "A1b2证";
const opensslPath = existsSync("/opt/homebrew/bin/openssl")
  ? "/opt/homebrew/bin/openssl"
  : "/usr/bin/openssl";

try {
  execFileSync(opensslPath, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-subj", "/CN=GDPower Adapter Test/O=Local Compatibility Test",
    "-keyout", keyPath,
    "-out", certificatePath,
    "-days", "1",
  ], { stdio: "ignore" });
  execFileSync(opensslPath, [
    "x509", "-in", certificatePath, "-outform", "DER",
    "-out", certificateDerPath,
  ]);

  const certificateEncode = readFileSync(certificateDerPath).toString("base64");
  const certificateDer = readFileSync(certificateDerPath);
  const result = await envelopedDataEncrypt({
    cert: { encode: certificateEncode, type: "", condition: "" },
    algo: -1,
    data: { text: Buffer.from(clearText, "utf8").toString("base64") },
  });
  assert.equal(result.result, 1);
  assert.equal(result.encData, result.envelopedData);
  assert.equal(result.encData, result.envelopedDataEncode);
  assert.equal(result.encData, result.encryptValue);
  assert.equal(result.encryptValueType, "base64");
  assert.equal(result.certObject.certCode, certificateEncode);
  writeFileSync(envelopePath, Buffer.from(result.encData, "base64"));

  const structure = execFileSync(opensslPath, [
    "cms", "-cmsout", "-inform", "DER", "-in", envelopePath, "-print",
  ], { encoding: "utf8" });
  assert.match(structure, /pkcs7-envelopedData/);
  assert.match(structure, /rsaEncryption/);
  assert.match(structure, /version: 2/);
  assert.match(structure, /d\.subjectKeyIdentifier/);
  assert.match(structure, /aes-128-cbc/);

  execFileSync(opensslPath, [
    "cms", "-decrypt", "-inform", "DER", "-in", envelopePath,
    "-recip", certificatePath, "-inkey", keyPath, "-out", decryptedPath,
  ]);
  assert.deepEqual(readFileSync(decryptedPath), Buffer.from(clearText, "utf8"));
  await assert.rejects(() => envelopedDataEncrypt({
    cert: { encode: certificateEncode },
    algo: 3,
    data: { text: clearText },
  }), /AES-CBC/);

  if (process.argv.includes("--hardware")) {
    const probe = JSON.parse(execFileSync(
      join(import.meta.dirname, "..", "build", "ft3000gm-hid-probe"),
      ["--include-certificate"],
      { encoding: "utf8" },
    ));
    const deviceResult = await envelopedDataEncrypt({
      cert: { encode: "", type: "device", condition: "CertType='Encrypt'" },
      algo: 0,
      data: {
        text: Buffer.from("device-certificate-test", "utf8").toString("base64"),
      },
    }, async () => probe);
    writeFileSync(envelopePath, Buffer.from(deviceResult.encData, "base64"));
    const deviceStructure = execFileSync(opensslPath, [
      "cms", "-cmsout", "-inform", "DER", "-in", envelopePath, "-print",
    ], { encoding: "utf8" });
    assert.match(deviceStructure, /pkcs7-envelopedData/);
    assert.match(deviceStructure, /aes-128-cbc/);
    const encryptionRecord = probe.certificates.find(
      (certificate) => certificate.file_id === "3002",
    );
    assert.ok(encryptionRecord, "USBKey encryption certificate 3002 is present");
    const encryptionCertificate = new X509Certificate(
      Buffer.from(encryptionRecord.encode, "base64"),
    );
    assert.equal(subjectKeyIdentifier(encryptionCertificate).length, 20);
    assert.match(deviceStructure, /d\.subjectKeyIdentifier/);
  
    const signingRecord = probe.certificates.find(
      (certificate) => certificate.file_id === "3001",
    );
    assert.ok(signingRecord, "USBKey signing certificate 3001 is present");
    const signingCertificateDer = Buffer.from(signingRecord.encode, "base64");
    const netcaCertificatePath = await buildCertificatePath(
      signingCertificateDer,
      true,
    );
    assert.equal(netcaCertificatePath.length, 2);
    const pathAttributes = buildSignedAttributes(
      Buffer.from("certificate-path-test", "utf8"),
      "sha256",
      signingCertificateDer,
    );
    writeFileSync(envelopePath, buildDetachedCms(
      signingCertificateDer,
      new X509Certificate(signingCertificateDer),
      pathAttributes,
      Buffer.alloc(256),
      false,
      "sha256",
      netcaCertificatePath,
    ));
    const pathStructure = execFileSync(opensslPath, [
      "cms", "-cmsout", "-inform", "DER", "-in", envelopePath, "-print",
    ], { encoding: "utf8" });
    assert.match(pathStructure, /CN=CCS NETCA L3 Organization CA/);
    assert.match(pathStructure, /CN=CCS NETCA Root L3/);
  
  }

  const signedContent = Buffer.from("issuer-signer-test", "utf8");
  const signedAttributes = buildSignedAttributes(
    signedContent,
    "sha256",
    certificateDer,
  );
  const issuerSignerCms = buildDetachedCms(
    certificateDer,
    new X509Certificate(certificateDer),
    signedAttributes,
    sign(
      "RSA-SHA256",
      signedAttributes,
      createPrivateKey(readFileSync(keyPath)),
    ),
    false,
    "sha256",
  );
  writeFileSync(envelopePath, issuerSignerCms);
  writeFileSync(signedContentPath, signedContent);
  const signerStructure = execFileSync(opensslPath, [
    "cms", "-cmsout", "-inform", "DER", "-in", envelopePath, "-print",
  ], { encoding: "utf8" });
  assert.match(signerStructure, /d\.issuerAndSerialNumber/);
  assert.doesNotMatch(signerStructure, /d\.subjectKeyIdentifier/);
  assert.match(signerStructure, /algorithm: sha256/);
  assert.match(signerStructure, /1\.2\.840\.113549\.1\.9\.16\.2\.47/);
  assert.doesNotMatch(signerStructure, /signingTime/);
  execFileSync(opensslPath, [
    "cms", "-verify", "-binary", "-inform", "DER", "-in", envelopePath,
    "-content", signedContentPath, "-noverify", "-out", verifiedContentPath,
  ], { stdio: "ignore" });
  assert.deepEqual(readFileSync(verifiedContentPath), signedContent);

  const legacyContent = Buffer.from("windows-business-profile", "utf8");
  const legacySignature = sign(
    "RSA-SHA1",
    legacyContent,
    createPrivateKey(readFileSync(keyPath)),
  );
  const legacyCms = buildNetcaLegacyDetachedCms(
    certificateDer,
    legacySignature,
    "sha1",
    "1.2.840.113549.1.1.1",
  );
  writeFileSync(envelopePath, legacyCms);
  writeFileSync(signedContentPath, legacyContent);
  const legacyStructure = execFileSync(opensslPath, [
    "cms", "-cmsout", "-inform", "DER", "-in", envelopePath, "-print",
  ], { encoding: "utf8" });
  assert.match(legacyStructure, /algorithm: sha1/);
  assert.match(legacyStructure, /algorithm: rsaEncryption/);
  assert.match(legacyStructure, /d\.issuerAndSerialNumber/);
  assert.match(legacyStructure, /signedAttrs:\s*<ABSENT>/);
  assert.match(legacyStructure, /unsignedAttrs:\s*<ABSENT>/);
  execFileSync(opensslPath, [
    "cms", "-verify", "-binary", "-inform", "DER", "-in", envelopePath,
    "-content", signedContentPath, "-noverify", "-out", verifiedContentPath,
  ], { stdio: "ignore" });
  assert.deepEqual(readFileSync(verifiedContentPath), legacyContent);

  console.log("EnvelopedData compatibility test passed");
} finally {
  rmSync(workDirectory, { recursive: true, force: true });
}
