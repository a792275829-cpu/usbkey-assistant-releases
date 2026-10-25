import { createDecipheriv, createHash, verify, X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { execFileAsync, trustStorePath, audit, summarize, bridgeVersion, captureRejectedCertificateSelector } from "./runtime.mjs";
import { readPublicCertificate, runProtectedSigner } from "./device-client.mjs";
import { deviceSelection } from "./device-selection.mjs";
import { pinSession, createPinSession } from "./pin-session.mjs";
import { certificateObject, certificateInventory, matchingCertificates, selectCertificate,
  publicCertificateRecord, assertPrivateKeyContainer } from "./certificates.mjs";
import {
  buildAesCbcEnvelopedData, buildDetachedCms, buildNetcaLegacyDetachedCms,
  buildSignedAttributes, certificateKeyUsage, certificateSupportsEncryption, certificateIssuerAndSerial,
  decodeCertificateEncode, parseEnvelopedData, selectEncryptionCertificate,
  sha1DigestInfo, sha256DigestInfo, subjectKeyIdentifier, unwrapRsaSessionKey,
} from "./cms.mjs";

async function observeCertificates(reader, authentication) {
  try {
    const probe = await reader();
    authentication.reconcileBindings(certificateInventory(probe).records.map((r) => r.binding));
    return probe;
  } catch (error) { authentication.invalidate(); throw error; }
}

let trustedCaCertificatesPromise = null;

async function readTrustedCaCertificates() {
  if (!existsSync(trustStorePath)) {
    throw new Error("NETCA 信任证书库缺失");
  }
  if (trustedCaCertificatesPromise === null) {
    trustedCaCertificatesPromise = execFileAsync(
      "/usr/bin/sqlite3",
      ["-noheader", trustStorePath, "SELECT hex(cert) FROM ca ORDER BY id"],
      { encoding: "utf8", timeout: 10000, maxBuffer: 4 * 1024 * 1024 },
    ).then(({ stdout }) => stdout.trim().split(/\r?\n/)
      .filter((line) => line.length !== 0)
      .map((line) => {
        if (line.length % 2 !== 0 || !/^[0-9A-F]+$/i.test(line)) {
          throw new Error("NETCA 信任证书库包含无效证书");
        }
        const certificateDer = Buffer.from(line, "hex");
        return {
          certificateDer,
          certificate: new X509Certificate(certificateDer),
        };
      })).catch((error) => {
      trustedCaCertificatesPromise = null;
      throw error;
    });
  }
  return trustedCaCertificatesPromise;
}

async function buildCertificatePath(leafCertificateDer, includeRoot) {
  const trustedCertificates = await readTrustedCaCertificates();
  const path = [];
  const usedFingerprints = new Set();
  let current = new X509Certificate(leafCertificateDer);

  for (let depth = 0; depth < 8 && current.issuer !== current.subject;
    depth += 1) {
    const parent = trustedCertificates.find((candidate) =>
      candidate.certificate.subject === current.issuer &&
      !usedFingerprints.has(candidate.certificate.fingerprint256) &&
      current.verify(candidate.certificate.publicKey));
    if (parent === undefined) {
      throw new Error("无法在 NETCA 信任库中构建签名证书链");
    }
    const isRoot = parent.certificate.subject === parent.certificate.issuer;
    if (!isRoot || includeRoot) path.push(parent.certificateDer);
    usedFingerprints.add(parent.certificate.fingerprint256);
    current = parent.certificate;
    if (isRoot) return path;
  }
  throw new Error("NETCA 签名证书链不完整");
}

async function envelopedDataEncrypt(parameter, probeReader = readPublicCertificate, selection = deviceSelection) {
  const requestedAlgorithm = parameter.algo === undefined || parameter.algo === null ? 4 : Number(parameter.algo);
  const algorithm = requestedAlgorithm <= 0 ? 4 : requestedAlgorithm;
  /*
   * The captured Windows client uses AES-128-CBC for both -1 (an explicitly
   * supplied certificate) and 0 (select the Encrypt certificate on device).
   * Algorithm id 6 remains available for callers that explicitly request
   * AES-256-CBC.
   */
  if (algorithm !== 4 && algorithm !== 6) {
    throw new Error("当前仅支持网站要求的 AES-CBC EnvelopedData 算法");
  }
  if (typeof parameter?.data?.text !== "string") {
    throw new Error("待加密文本格式无效");
  }
  const encodedClearText = parameter.data.text;
  if (encodedClearText.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encodedClearText)) {
    throw new Error("待加密文本不是有效的 Base64 数据");
  }
  const clearText = Buffer.from(encodedClearText, "base64");
  if (clearText.toString("base64") !== encodedClearText) {
    throw new Error("待加密文本不是规范的 Base64 数据");
  }
  if (clearText.length > 1024 * 1024) throw new Error("待加密文本过长");

  const suppliedEncode = parameter?.cert?.encode;
  let certificateDer;
  let certificateSource = "supplied";
  let certificateFileId;
  if (typeof suppliedEncode === "string" && suppliedEncode.length !== 0) {
    certificateDer = decodeCertificateEncode(suppliedEncode);
  } else {
    const selected = selectCertificate(await probeReader(), parameter.cert ?? {}, "Encrypt", undefined, selection.current());
    certificateDer = selected.certificateDer;
    certificateFileId = selected.fileId;
    certificateSource = "usbkey";
  }
  const certificate = new X509Certificate(certificateDer);
  const keyBits = algorithm === 6 ? 256 : 128;
  const encoded = buildAesCbcEnvelopedData(
    certificate,
    clearText,
    keyBits,
  ).toString("base64");
  audit("enveloped_data_created", {
    algorithm: `AES-${keyBits}-CBC`,
    keyEncryption: "RSA-PKCS1-v1_5",
    recipientIdentifier: "subjectKeyIdentifier",
    certificateSource,
    certificateFileId,
    contentEncoding: "base64-decoded",
    contentBytes: clearText.length,
    cmsBytes: Buffer.byteLength(encoded, "base64"),
  });
  return {
    result: 1,
    encData: encoded,
    envelopedData: encoded,
    envelopedDataEncode: encoded,
    cipherText: encoded,
    value: encoded,
    encryptValue: encoded,
    encryptValueType: "base64",
    certObject: certificateObject(certificateDer),
  };
}

async function signedDataSign(parameter, dependencies = {}) {
  const usesNativeDefaults = parameter.algo === undefined ||
    parameter.algo === null;
  const algorithm = usesNativeDefaults
    ? 2
    : Number(parameter.algo);
  if (algorithm !== 2 && algorithm !== 4) {
    throw new Error("当前仅支持网站要求的 SHA1withRSA/SHA256withRSA 算法");
  }
  if (Number(parameter.detached) !== 1) {
    throw new Error("当前仅支持分离式 SignedData 签名");
  }
  if (typeof parameter?.data?.text !== "string") {
    throw new Error("待签名文本格式无效");
  }
  const encodedContent = parameter.data.text;
  if (encodedContent.length === 0) throw new Error("待签名文本为空");
  const includeCertOption = Number(parameter.includeCertOption ?? 2);
  if (![0, 1, 2, 3].includes(includeCertOption)) throw new Error("网站请求了不受支持的证书链包含选项");
  const authentication = dependencies.authentication ?? pinSession;
  const probe = await observeCertificates(dependencies.probeReader ?? readPublicCertificate, authentication);
  const selected = selectCertificate(probe, parameter.cert ?? {}, "Sign", undefined, (dependencies.selection ?? deviceSelection).current());
  if (!dependencies.signer) assertPrivateKeyContainer(selected, "Sign");
  const certificateDer = selected.certificateDer;
  const certificateEncode = certificateDer.toString("base64");
  const certificate = selected.certificate;
  /* KeyX JSON-RPC transports SignedData input in data.text as canonical
   * Base64 for both explicit and native-default algorithm selection.
   */
  if (encodedContent.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encodedContent)) {
    throw new Error("待签名文本不是有效的 Base64 数据");
  }
  const content = Buffer.from(encodedContent, "base64");
  if (content.toString("base64") !== encodedContent) {
    throw new Error("待签名文本不是规范的 Base64 数据");
  }
  const contentEncoding = "base64-decoded";
  const digestName = algorithm === 2 ? "sha1" : "sha256";
  const digestInfo = algorithm === 2
    ? sha1DigestInfo(content)
    : sha256DigestInfo(content);
  if (parameter.clearPwdCache === true) authentication.clearCachedCertificatePin();
  const signer = dependencies.signer ?? ((pin, data) => runProtectedSigner(pin, data, "--sign-digest-info", selected));
  return authentication.withAuthentication(selected.binding, parameter.certPwd === "" ? undefined : parameter.certPwd, async (pin) => {
    const signature = await signer(pin, digestInfo, selected);
    if (!verify(algorithm === 2 ? "RSA-SHA1" : "RSA-SHA256", content, certificate.publicKey, signature)) {
      throw new Error("USBKey 返回的 RSA 签名未通过公钥自检");
    }
    /* Preserve the captured site's successful CMS byte profile: leaf-only,
     * no signedAttrs, issuerAndSerialNumber. This is a compatibility profile,
     * not a claim that all original-client signing options behave this way.
     */
    const signatureAlgorithmOid = usesNativeDefaults
      ? "1.2.840.113549.1.1.1"
      : algorithm === 2
        ? "1.2.840.113549.1.1.5"
        : "1.2.840.113549.1.1.11";
    const cms = buildNetcaLegacyDetachedCms(
      certificateDer,
      signature,
      digestName,
      signatureAlgorithmOid,
    ).toString("base64");
    audit("signed_data_created", {
      algorithm: algorithm === 2 ? "SHA1withRSA" : "SHA256withRSA",
      contentEncoding,
      detached: true,
      contentBytes: content.length,
      signatureBytes: signature.length,
      cmsBytes: Buffer.byteLength(cms, "base64"),
      includeCertOption,
      includedCertificateCount: 1,
      signerIdentifier: "issuerAndSerialNumber",
      signedAttributeProfile: "none",
      windowsCompatibilityProfile: usesNativeDefaults
        ? "business-default-sha1-rsaEncryption"
        : "explicit-algorithm",
    });
    return {
      result: 1,
      signCert: certificateEncode,
      signedData: cms,
      signedDataEncode: cms,
      signValue: cms,
      value: cms,
      certObject: publicCertificateRecord(selected),
    };
  });
}

async function envelopedDataDecrypt(parameter, dependencies = {}) {
  if (parameter.savefileName) throw new Error("当前解密接口仅支持页面内返回数据");
  const envelope = parseEnvelopedData(parameter.encData);
  const authentication = dependencies.authentication ?? (dependencies.pinReader
    ? createPinSession({ prompt: dependencies.pinReader }) : pinSession);
  const probe = await observeCertificates(dependencies.probeReader ?? readPublicCertificate, authentication);
  const findRecipient = (record) => {
    const ski = subjectKeyIdentifier(record.certificate);
    const issuerSerial = certificateIssuerAndSerial(record.certificateDer);
    return envelope.recipients.find((r) => r.ski ? r.ski.equals(ski) : r.issuerSerial.equals(issuerSerial));
  };
  const inventory = certificateInventory(probe);
  if (!inventory.records.some((r) => r.usage === "Encrypt" && findRecipient(r))) {
    // Public recipient identifiers only. Do not retain encrypted quotation
    // contents, RSA blocks, IVs, PINs, or decrypted business data.
    const idHash = (bytes) => createHash("sha256").update(bytes).digest("hex");
    audit("envelope_recipient_not_found", {
      recipientIdentifiers: envelope.recipients.map((r) => ({ type: r.ski ? "ski" : "issuerSerial",
        hash: idHash(r.ski ?? r.issuerSerial) })),
      deviceCertificates: inventory.records.map((r) => ({ deviceId: r.deviceId, fileId: r.fileId, usage: r.usage,
        skiHash: idHash(subjectKeyIdentifier(r.certificate)),
        issuerSerialHash: idHash(certificateIssuerAndSerial(r.certificateDer)),
        matchesRecipient: Boolean(findRecipient(r)) })),
    });
  }
  const selected = selectCertificate(probe, parameter.cert ?? {}, "Encrypt", (r) => Boolean(findRecipient(r)),
    (dependencies.selection ?? deviceSelection).current());
  const recipient = findRecipient(selected);
  if (recipient.encryptedKey.length !== 256) throw new Error("当前仅支持 RSA-2048 数字信封");
  if (!dependencies.decryptBlock && !dependencies.decryptBlockWithoutPin && !dependencies.decryptBlockWithPin) {
    assertPrivateKeyContainer(selected, "Encrypt");
  }
  const decryptWithPin = dependencies.decryptBlockWithPin ?? dependencies.decryptBlock ??
    ((pin, bytes) => runProtectedSigner(pin, bytes, "--decrypt-rsa-block", selected));
  const decryptWithoutPin = dependencies.decryptBlockWithoutPin ??
    (dependencies.decryptBlock ? ((bytes) => dependencies.decryptBlock(undefined, bytes)) :
      ((bytes) => runProtectedSigner(null, bytes, "--decrypt-rsa-block-no-pin", selected)));
  return authentication.withAuthentication(selected.binding, (parameter.certPwd || dependencies.authenticationPin),
    async (pin) => {
      let block, key, plaintext;
      try {
        block = pin === null ? await decryptWithoutPin(recipient.encryptedKey) : await decryptWithPin(pin, recipient.encryptedKey);
        key = unwrapRsaSessionKey(block, recipient.encryptedKey, selected.certificate, envelope.keyBits / 8);
        const cipher = createDecipheriv(`aes-${envelope.keyBits}-cbc`, key, envelope.iv);
        plaintext = Buffer.concat([cipher.update(envelope.ciphertext), cipher.final()]);
        const clearText = plaintext.toString("base64");
        audit("enveloped_data_decrypted", { algorithm: `AES-${envelope.keyBits}-CBC`,
          certificateFileId: selected.fileId, contentBytes: plaintext.length });
        return { clearValue: clearText, clearEncodeType: "base64", clearText,
          decryptValue: clearText, decryptValueType: "base64", algo: envelope.keyBits === 256 ? 6 : 4,
          certObject: publicCertificateRecord(selected) };
      } finally { block?.fill(0); key?.fill(0); plaintext?.fill(0); }
    }, { allowWithoutPin: true });
}

function success(request, responseEntity) {
  return {
    responseVersion: 1,
    requestVersion: request?.requestVersion ?? 1,
    lwsObjectId: request?.lwsObjectId,
    requestOrigin: request?.requestOrigin,
    requestId: request?.requestId,
    responseResult: { status: 0, msg: "成功" },
    responseEntity,
  };
}

function failure(request, message, status = -11000) {
  return {
    responseVersion: 1,
    requestVersion: request?.requestVersion ?? 1,
    lwsObjectId: request?.lwsObjectId,
    requestOrigin: request?.requestOrigin,
    requestId: request?.requestId,
    responseResult: { status, msg: message },
    responseEntity: {},
  };
}

async function dispatchOperation(request, dependencies = {}) {
  const authentication = dependencies.authentication ?? pinSession;
  const probeReader = () => observeCertificates(dependencies.probeReader ?? readPublicCertificate, authentication);
  const name = request?.requestQuery?.function;
  const parameter = request?.requestQuery?.param ?? {};
  audit("rpc_request", {
    requestId: request?.requestId,
    method: String(name),
    parameterShape: summarize(parameter),
  });

  if (["GetVersionInfo1", "GetVersionInfo", "GetClientVersionInfo"].includes(name)) {
    return success(request, {
      version: `macOS-ft3000gm-${bridgeVersion}`,
      clientVersion: `macOS-ft3000gm-${bridgeVersion}`,
    });
  }

  if (name === "IsInsertKey") {
    const probe = await probeReader();
    const { devices } = certificateInventory(probe);
    const connected = devices.filter((d) => d.device_found !== false);
    return success(request, { insertCount: connected.length, sn: connected[0]?.device_sn ?? "",
      type: connected[0]?.device_type ?? 47 });
  }

  if (name === "GetCertStringAttribute") {
    if (Number(parameter.id) !== -1) return failure(request, "当前仅支持获取公有证书编码", -11001);
    const record = selectCertificate(await probeReader(), parameter.cert ?? {},
      parameter.cert?.encode || parameter.cert?.certCode || parameter.cert?.condition ? undefined : "Sign",
      undefined, (dependencies.selection ?? deviceSelection).current());
    return success(request, { certCode: record.certificateDer.toString("base64"), certEncode: record.certificateDer.toString("base64") });
  }

  if (name === "GetCertList") {
    if (parameter.type !== undefined && ![0, 1, 2].includes(Number(parameter.type))) throw new Error("证书列表类型无效");
    // Original type=1 accepts encryption-only KeyUsage (mask 0x19c);
    // type=2 accepts signing usage and current validity (attribute 0x22).
    const probe = await probeReader();
    const inventory = certificateInventory(probe);
    authentication.reconcileBindings(inventory.records.map((r) => r.binding));
    const certInfo = matchingCertificates(probe, parameter.cert ?? {}).filter((record) => {
      const usage = certificateKeyUsage(record.certificateDer);
      if (Number(parameter.type) === 1) return usage !== null && (usage & 0x19c) !== 0 && (usage & ~0x19c) === 0;
      if (Number(parameter.type) === 2) return usage !== null && (usage & 3) !== 0 &&
        (dependencies.now?.() ?? Date.now()) >= Date.parse(record.certificate.validFrom) &&
        (dependencies.now?.() ?? Date.now()) <= Date.parse(record.certificate.validTo);
      return true;
    }).map(publicCertificateRecord);
    return success(request, { deviceCount: inventory.devices.filter((d) => d.device_found !== false).length,
      certCount: certInfo.length, certInfo, certList: certInfo, certs: certInfo });
  }

  if (name === "MonitorDevice") {
    if (!dependencies.monitor || !dependencies.connection) return failure(request, "设备监测需要 WebSocket 连接", -11001);
    dependencies.monitor.subscribe(dependencies.connection, request, parameter.delayTime ?? 0);
    return success(request, {});
  }

  if (name === "SignedDataSign") {
    return success(request, await signedDataSign(parameter, dependencies));
  }

  if (name === "EnvelopedDataEncrypt") {
    return success(request, await envelopedDataEncrypt(parameter, probeReader, dependencies.selection ?? deviceSelection));
  }

  if (name === "EnvelopedDataDecrypt") {
    return success(request, await envelopedDataDecrypt(parameter, dependencies));
  }

  if (name === "ClearPwdCache") {
    await authentication.clearCachedCertificatePin();
    audit("password_cache_cleared", {
      cacheEntries: 1,
      authenticatedSessionLeasePreserved: await authentication.hasAuthenticatedSessionPin(),
    });
    return success(request, { result: 1 });
  }

  return failure(
    request,
    `macOS 桥暂不支持 ${String(name)}`,
    -11001,
  );
}

async function dispatch(request, dependencies = {}) {
  try { return await dispatchOperation(request, dependencies); }
  catch (error) {
    if (request?.requestQuery?.function === "GetCertStringAttribute" && Number(request.requestQuery.param?.id) === -1) {
      try { captureRejectedCertificateSelector(request.requestQuery.param?.cert); }
      catch { /* Diagnostics must never change the original RPC outcome. */ }
    }
    if (error?.code === "USBKEY_PIN_REJECTED" && ["SignedDataSign", "EnvelopedDataDecrypt"].includes(request?.requestQuery?.function)) {
      return success(request, { result: error.netcaResult, retrynum: error.retries });
    }
    throw error;
  }
}


export { dispatch, success, failure, signedDataSign,
  buildAesCbcEnvelopedData,
  buildCertificatePath,
  buildDetachedCms,
  buildNetcaLegacyDetachedCms,
  buildSignedAttributes,
  certificateSupportsEncryption,
  envelopedDataEncrypt,
  envelopedDataDecrypt,
  parseEnvelopedData,
  selectEncryptionCertificate,
  sha256DigestInfo,
  subjectKeyIdentifier,
};
