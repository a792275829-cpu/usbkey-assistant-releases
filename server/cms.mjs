import { constants, createCipheriv, createHash, publicEncrypt, randomBytes, X509Certificate } from "node:crypto";

function derLength(length) {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error("DER length is invalid");
  }
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  for (let value = length; value !== 0; value >>>= 8) {
    bytes.unshift(value & 0xff);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, ...parts) {
  const content = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function oid(value) {
  const components = value.split(".").map(Number);
  if (components.length < 2 || components.some((part) =>
    !Number.isSafeInteger(part) || part < 0)) {
    throw new Error("OID is invalid");
  }
  const encoded = [components[0] * 40 + components[1]];
  for (const component of components.slice(2)) {
    const bytes = [component & 0x7f];
    for (let rest = Math.floor(component / 128); rest !== 0;
      rest = Math.floor(rest / 128)) {
      bytes.unshift(0x80 | (rest & 0x7f));
    }
    encoded.push(...bytes);
  }
  return der(0x06, Buffer.from(encoded));
}

function sequence(...parts) {
  return der(0x30, ...parts);
}

function setOf(...parts) {
  return der(0x31, ...parts.sort(Buffer.compare));
}

function algorithmIdentifier(algorithmOid) {
  return sequence(oid(algorithmOid), der(0x05));
}

function algorithmIdentifierWithoutParameters(algorithmOid) {
  return sequence(oid(algorithmOid));
}

function algorithmIdentifierWithParameters(algorithmOid, parameters) {
  return sequence(oid(algorithmOid), parameters);
}

function derInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0x7fffffff) {
    throw new Error("DER integer is invalid");
  }
  const bytes = [];
  for (let rest = value; rest !== 0; rest >>>= 8) bytes.unshift(rest & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}

function readDer(buffer, offset = 0) {
  if (offset + 2 > buffer.length) throw new Error("DER value is truncated");
  const tag = buffer[offset];
  let length = buffer[offset + 1];
  let headerLength = 2;
  if ((length & 0x80) !== 0) {
    const lengthBytes = length & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 6 ||
        offset + 2 + lengthBytes > buffer.length) {
      throw new Error("DER length is invalid");
    }
    length = 0;
    for (let i = 0; i < lengthBytes; i += 1) {
      length = length * 256 + buffer[offset + 2 + i];
    }
    headerLength += lengthBytes;
  }
  const contentStart = offset + headerLength;
  const end = contentStart + length;
  if (end > buffer.length) throw new Error("DER value is truncated");
  return { tag, start: offset, contentStart, end, length };
}

function subjectKeyIdentifier(certificate) {
  const spki = Buffer.from(certificate.publicKey.export({
    format: "der",
    type: "spki",
  }));
  const outer = readDer(spki);
  const algorithm = readDer(spki, outer.contentStart);
  const publicKeyBits = readDer(spki, algorithm.end);
  if (outer.tag !== 0x30 || publicKeyBits.tag !== 0x03 ||
      publicKeyBits.length < 2 || spki[publicKeyBits.contentStart] !== 0) {
    throw new Error("证书公钥格式不受支持");
  }
  return createHash("sha1")
    .update(spki.subarray(publicKeyBits.contentStart + 1, publicKeyBits.end))
    .digest();
}

function signedAttribute(attributeOid, value) {
  return sequence(oid(attributeOid), setOf(value));
}

function signingCertificateV2(certificateDer) {
  if (!Buffer.isBuffer(certificateDer) || certificateDer.length === 0) {
    throw new Error("签名证书 DER 格式无效");
  }
  /*
   * NETCA's default SignedData configuration enables the ETSI
   * SigningCertificateV2 attribute.  SHA-256 is the ASN.1 DEFAULT for
   * ESSCertIDv2, so the hashAlgorithm field is deliberately omitted.
  */
  const certHash = createHash("sha256").update(certificateDer).digest();
  const { issuer, serialNumber } = certificateIssuerAndSerialParts(
    certificateDer,
  );
  const issuerSerial = sequence(
    sequence(der(0xa4, issuer)),
    serialNumber,
  );
  const essCertIdV2 = sequence(der(0x04, certHash), issuerSerial);
  const certs = sequence(essCertIdV2);
  return sequence(certs);
}

function buildSignedAttributes(content, digestName = "sha256",
                               certificateDer = undefined) {
  const contentDigest = createHash(digestName).update(content).digest();
  const attributes = [
    signedAttribute("1.2.840.113549.1.9.3", oid("1.2.840.113549.1.7.1")),
    signedAttribute("1.2.840.113549.1.9.4", der(0x04, contentDigest)),
  ];
  if (certificateDer !== undefined) {
    attributes.push(signedAttribute(
      "1.2.840.113549.1.9.16.2.47",
      signingCertificateV2(certificateDer),
    ));
  }
  return setOf(...attributes);
}

function sha256DigestInfo(content) {
  const digest = createHash("sha256").update(content).digest();
  return Buffer.concat([
    Buffer.from("3031300d060960864801650304020105000420", "hex"),
    digest,
  ]);
}

function sha1DigestInfo(content) {
  const digest = createHash("sha1").update(content).digest();
  return Buffer.concat([
    Buffer.from("3021300906052b0e03021a05000414", "hex"),
    digest,
  ]);
}


function buildDetachedCms(certificateDer, certificate, signedAttributes,
                          signature, useSubjectKeyId = true,
                          digestName = "sha256",
                          additionalCertificates = []) {
  const dataOid = oid("1.2.840.113549.1.7.1");
  const digestAlgorithm = algorithmIdentifier(
    digestName === "sha1"
      ? "1.3.14.3.2.26"
      : "2.16.840.1.101.3.4.2.1",
  );
  const signedAttributesTlv = readDer(signedAttributes);
  const signerInfo = sequence(
    derInteger(useSubjectKeyId ? 3 : 1),
    useSubjectKeyId
      ? der(0x80, subjectKeyIdentifier(certificate))
      : certificateIssuerAndSerial(certificateDer),
    digestAlgorithm,
    der(0xa0, signedAttributes.subarray(
      signedAttributesTlv.contentStart,
      signedAttributesTlv.end,
    )),
    algorithmIdentifier("1.2.840.113549.1.1.1"),
    der(0x04, signature),
  );
  const certificateSet = [certificateDer, ...additionalCertificates]
    .filter((candidate, index, values) => values.findIndex((other) =>
      candidate.equals(other)) === index)
    .sort(Buffer.compare);
  const signedData = sequence(
    derInteger(useSubjectKeyId ? 3 : 1),
    setOf(digestAlgorithm),
    sequence(dataOid),
    der(0xa0, ...certificateSet),
    setOf(signerInfo),
  );
  return sequence(
    oid("1.2.840.113549.1.7.2"),
    der(0xa0, signedData),
  );
}

function certificateIssuerAndSerialParts(certificateDer) {
  const certificate = readDer(certificateDer);
  if (certificate.tag !== 0x30 || certificate.end !== certificateDer.length) {
    throw new Error("证书 DER 格式无效");
  }
  const tbsCertificate = readDer(certificateDer, certificate.contentStart);
  if (tbsCertificate.tag !== 0x30) throw new Error("证书主体格式无效");

  let offset = tbsCertificate.contentStart;
  let serialNumber = readDer(certificateDer, offset);
  if (serialNumber.tag === 0xa0) {
    offset = serialNumber.end;
    serialNumber = readDer(certificateDer, offset);
  }
  if (serialNumber.tag !== 0x02) throw new Error("证书序列号格式无效");

  const signatureAlgorithm = readDer(certificateDer, serialNumber.end);
  if (signatureAlgorithm.tag !== 0x30) {
    throw new Error("证书签名算法格式无效");
  }
  const issuer = readDer(certificateDer, signatureAlgorithm.end);
  if (issuer.tag !== 0x30) throw new Error("证书颁发者格式无效");

  return {
    issuer: certificateDer.subarray(issuer.start, issuer.end),
    serialNumber: certificateDer.subarray(serialNumber.start, serialNumber.end),
  };
}

function certificateIssuerAndSerial(certificateDer) {
  const { issuer, serialNumber } = certificateIssuerAndSerialParts(
    certificateDer,
  );
  return sequence(issuer, serialNumber);
}


function decodeCertificateEncode(value) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > 256 * 1024) {
    throw new Error("加密证书编码无效");
  }
  const compact = value.replace(/\s/g, "");
  const pemMatch = compact.match(
    /^-----BEGINCERTIFICATE-----(.+)-----ENDCERTIFICATE-----$/,
  );
  const encoded = pemMatch ? pemMatch[1] : compact;
  if (encoded.length === 0 || encoded.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error("加密证书不是有效的 Base64 DER 数据");
  }
  const certificateDer = Buffer.from(encoded, "base64");
  if (certificateDer.toString("base64") !== encoded) {
    throw new Error("加密证书不是规范的 Base64 DER 数据");
  }
  return certificateDer;
}

function certificateKeyUsage(certificateDer) {
  const certificate = readDer(certificateDer);
  const tbsCertificate = readDer(certificateDer, certificate.contentStart);
  if (certificate.tag !== 0x30 || tbsCertificate.tag !== 0x30) return null;

  let offset = tbsCertificate.contentStart;
  let field = readDer(certificateDer, offset);
  if (field.tag === 0xa0) {
    offset = field.end;
    field = readDer(certificateDer, offset);
  }
  /* serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo */
  for (let index = 0; index < 6; index += 1) {
    field = readDer(certificateDer, offset);
    offset = field.end;
  }

  while (offset < tbsCertificate.end) {
    field = readDer(certificateDer, offset);
    offset = field.end;
    if (field.tag !== 0xa3) continue;
    const extensions = readDer(certificateDer, field.contentStart);
    if (extensions.tag !== 0x30) return null;
    let extensionOffset = extensions.contentStart;
    while (extensionOffset < extensions.end) {
      const extension = readDer(certificateDer, extensionOffset);
      extensionOffset = extension.end;
      if (extension.tag !== 0x30) continue;
      const extensionOid = readDer(certificateDer, extension.contentStart);
      if (extensionOid.tag !== 0x06) continue;
      const oidBytes = certificateDer.subarray(
        extensionOid.contentStart,
        extensionOid.end,
      );
      if (!oidBytes.equals(Buffer.from("551d0f", "hex"))) continue;

      let value = readDer(certificateDer, extensionOid.end);
      if (value.tag === 0x01) value = readDer(certificateDer, value.end);
      if (value.tag !== 0x04) return null;
      const usage = readDer(certificateDer, value.contentStart);
      if (usage.tag !== 0x03 || usage.length < 2) return null;
      const firstUsageByte = certificateDer[usage.contentStart + 1];
      /* keyEncipherment, dataEncipherment, or keyAgreement */
      let mask = 0;
      for (let bit = 0; bit < 8; bit++) if (firstUsageByte & (0x80 >> bit)) mask |= 1 << bit;
      if (usage.length > 2 && certificateDer[usage.contentStart + 2] & 0x80) mask |= 0x100;
      return mask;
    }
  }
  return null;
}

function certificateSupportsEncryption(certificateDer) {
  return ((certificateKeyUsage(certificateDer) ?? 0) & 0x1c) !== 0;
}

function selectEncryptionCertificate(probe) {
  const devices = probe.devices ?? [probe];
  const selected = [];
  for (const device of devices) {
    const candidates = device.certificates ?? [{ file_id: "unknown", encode: device.certificate_base64 }];
    for (const candidate of candidates) {
      try {
        const certificateDer = decodeCertificateEncode(candidate.encode);
        if (certificateSupportsEncryption(certificateDer)) selected.push({ certificateDer,
          fileId: String(candidate.file_id ?? "unknown"), deviceId: device.device_id });
      } catch { /* Ignore malformed public records. */ }
    }
  }
  if (!selected.length) throw new Error("USBKey 中未找到有效的加密证书");
  if (selected.length > 1) throw new Error("匹配到多张加密证书，请指定设备或证书");
  return selected[0];
}

function buildAesCbcEnvelopedData(certificate, clearText, keyBits = 128) {
  if (certificate.publicKey.asymmetricKeyType !== "rsa") {
    throw new Error("EnvelopedData 当前仅支持 RSA 加密证书");
  }

  if (keyBits !== 128 && keyBits !== 256) {
    throw new Error("EnvelopedData AES 密钥长度无效");
  }
  const contentEncryptionKey = randomBytes(keyBits / 8);
  const iv = randomBytes(16);
  const cipher = createCipheriv(
    keyBits === 128 ? "aes-128-cbc" : "aes-256-cbc",
    contentEncryptionKey,
    iv,
  );
  const encryptedContent = Buffer.concat([
    cipher.update(clearText),
    cipher.final(),
  ]);
  const encryptedKey = publicEncrypt({
    key: certificate.publicKey,
    padding: constants.RSA_PKCS1_PADDING,
  }, contentEncryptionKey);

  const recipientInfo = sequence(
    derInteger(2),
    der(0x80, subjectKeyIdentifier(certificate)),
    algorithmIdentifier("1.2.840.113549.1.1.1"),
    der(0x04, encryptedKey),
  );
  const encryptedContentInfo = sequence(
    oid("1.2.840.113549.1.7.1"),
    algorithmIdentifierWithParameters(
      keyBits === 128
        ? "2.16.840.1.101.3.4.1.2"
        : "2.16.840.1.101.3.4.1.42",
      der(0x04, iv),
    ),
    der(0x80, encryptedContent),
  );
  const envelopedData = sequence(
    derInteger(2),
    setOf(recipientInfo),
    encryptedContentInfo,
  );
  return sequence(
    oid("1.2.840.113549.1.7.3"),
    der(0xa0, envelopedData),
  );
}


function buildNetcaLegacyDetachedCms(certificateDer, signature,
                                      digestName = "sha1",
                                      signatureAlgorithmOid = undefined) {
  const digestOid = digestName === "sha1"
    ? "1.3.14.3.2.26"
    : "2.16.840.1.101.3.4.2.1";
  const signatureOid = signatureAlgorithmOid ?? (digestName === "sha1"
    ? "1.2.840.113549.1.1.5"
    : "1.2.840.113549.1.1.11");
  const digestAlgorithm = algorithmIdentifierWithoutParameters(digestOid);
  const signerInfo = sequence(
    derInteger(1),
    certificateIssuerAndSerial(certificateDer),
    digestAlgorithm,
    algorithmIdentifier(signatureOid),
    der(0x04, signature),
  );
  const signedData = sequence(
    derInteger(1),
    setOf(digestAlgorithm),
    sequence(oid("1.2.840.113549.1.7.1")),
    der(0xa0, certificateDer),
    setOf(signerInfo),
  );
  return sequence(
    oid("1.2.840.113549.1.7.2"),
    der(0xa0, signedData),
  );
}


// Strict DER parser for the RSA/AES CMS profile emitted by the Windows client.
function derChildren(buffer, parent) {
  const result = [];
  for (let offset = parent.contentStart; offset < parent.end;) {
    const item = readDer(buffer, offset);
    if (item.end > parent.end) throw new Error("数字信封 DER 边界无效");
    result.push(item);
    offset = item.end;
  }
  return result;
}

function parseEnvelopedData(encoded) {
  if (typeof encoded !== "string" || encoded.length > 2 * 1024 * 1024 ||
      encoded.length === 0 || encoded.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error("数字信封 Base64 格式无效");
  }
  const b = Buffer.from(encoded, "base64");
  if (b.toString("base64") !== encoded) throw new Error("数字信封编码无效");
  const bytes = (item) => b.subarray(item.contentStart, item.end);
  const full = (item) => b.subarray(item.start, item.end);
  const expect = (condition) => {
    if (!condition) throw new Error("不支持的数字信封结构");
  };
  const root = readDer(b);
  expect(root.tag === 0x30 && root.end === b.length);
  const ci = derChildren(b, root);
  expect(ci.length === 2 && full(ci[0]).equals(oid("1.2.840.113549.1.7.3")) && ci[1].tag === 0xa0);
  const wrapper = derChildren(b, ci[1]);
  expect(wrapper.length === 1 && wrapper[0].tag === 0x30);
  const env = derChildren(b, wrapper[0]);
  expect(env.length === 3 && env[0].tag === 2 && env[1].tag === 0x31 && env[2].tag === 0x30);
  const recipients = derChildren(b, env[1]).map((entry) => {
    expect(entry.tag === 0x30);
    const fields = derChildren(b, entry);
    expect(fields.length === 4 && fields[0].tag === 2 && fields[2].tag === 0x30 && fields[3].tag === 4);
    const alg = derChildren(b, fields[2]);
    expect(alg.length >= 1 && full(alg[0]).equals(oid("1.2.840.113549.1.1.1")));
    expect(fields[1].tag === 0x80 || fields[1].tag === 0x30);
    return { ski: fields[1].tag === 0x80 ? bytes(fields[1]) : null,
      issuerSerial: fields[1].tag === 0x30 ? full(fields[1]) : null,
      encryptedKey: bytes(fields[3]) };
  });
  const content = derChildren(b, env[2]);
  expect(content.length === 3 && full(content[0]).equals(oid("1.2.840.113549.1.7.1")) && content[1].tag === 0x30 && content[2].tag === 0x80);
  const alg = derChildren(b, content[1]);
  expect(alg.length === 2 && alg[1].tag === 4 && alg[1].length === 16);
  const keyBits = full(alg[0]).equals(oid("2.16.840.1.101.3.4.1.2")) ? 128
    : full(alg[0]).equals(oid("2.16.840.1.101.3.4.1.42")) ? 256 : 0;
  expect(keyBits !== 0 && content[2].length > 0 && content[2].length % 16 === 0);
  return { recipients, keyBits, iv: bytes(alg[1]), ciphertext: bytes(content[2]) };
}

function unwrapRsaSessionKey(block, encryptedKey, certificate, keyBytes) {
  // Verify the raw hardware operation against the selected public key before
  // interpreting PKCS#1 v1.5 type-2 padding or using the AES key.
  if (block.length !== 256 || !publicEncrypt({ key: certificate.publicKey,
    padding: constants.RSA_NO_PADDING }, block).equals(encryptedKey)) {
    throw new Error("USBKey 解密结果未通过公钥自检");
  }
  const separator = block.indexOf(0, 2);
  if (block[0] !== 0 || block[1] !== 2 || separator < 10 ||
      block.length - separator - 1 !== keyBytes) {
    throw new Error("数字信封 RSA 密钥填充无效");
  }
  return Buffer.from(block.subarray(separator + 1));
}


export {
  buildAesCbcEnvelopedData, buildDetachedCms, buildNetcaLegacyDetachedCms,
  buildSignedAttributes, certificateKeyUsage, certificateSupportsEncryption, certificateIssuerAndSerial,
  decodeCertificateEncode, parseEnvelopedData, selectEncryptionCertificate,
  sha1DigestInfo, sha256DigestInfo, subjectKeyIdentifier, unwrapRsaSessionKey,
};
