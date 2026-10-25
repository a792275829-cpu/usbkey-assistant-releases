import { createHash, X509Certificate } from "node:crypto";
import { certificateKeyUsage, certificateSupportsEncryption, decodeCertificateEncode } from "./cms.mjs";

const fingerprint = (der) => createHash("sha256").update(der).digest("hex").toUpperCase();
const compactHex = (value) => String(value).replace(/[:\s]/g, "").toUpperCase();

function certificateObject(der) {
  const cert = new X509Certificate(der);
  const legacy = cert.toLegacyObject();
  const result = { certCode: der.toString("base64"), certEncode: der.toString("base64"),
    encode: der.toString("base64"), subject: cert.subject, issuer: cert.issuer,
    serialNumber: cert.serialNumber, Thumbprint: compactHex(cert.fingerprint),
    Thumbprint256: compactHex(cert.fingerprint256),
    validFromDate: new Date(cert.validFrom).toISOString(),
    validToDate: new Date(cert.validTo).toISOString(),
    publicKeyAlgorithmName: cert.publicKey.asymmetricKeyType,
    publicKeyBits: cert.publicKey.asymmetricKeyDetails?.modulusLength };
  if (cert.publicKey.asymmetricKeyType === "rsa") { result.publicKeyAlgorithm = 1; result.publicKeyType = 1; }
  const keyUsage = certificateKeyUsage(der);
  if (keyUsage !== null) result.keyUsage = keyUsage;
  for (const [prefix, source] of [["subject", legacy.subject], ["issuer", legacy.issuer]]) {
    for (const field of ["CN", "O", "OU", "L", "ST", "C"]) {
      if (source?.[field] !== undefined) result[prefix + field] = source[field];
    }
    if (source?.emailAddress !== undefined) result[prefix + "Email"] = source.emailAddress;
  }
  return result;
}

function certificateInventory(probe) {
  const devices = Array.isArray(probe.devices) ? probe.devices : [probe];
  const records = [];
  for (const device of devices) {
    const candidates = device.certificates ?? (device.certificate_base64
      ? [{ file_id: device.certificate_file_id ?? "unknown", encode: device.certificate_base64 }] : []);
    const valid = [];
    for (const record of candidates) {
      try {
        const certificateDer = decodeCertificateEncode(record.encode);
        const certificate = new X509Certificate(certificateDer);
        const encrypt = certificateSupportsEncryption(certificateDer);
        // FT3000's known signing/encryption files provide an additional role
        // boundary. Never reinterpret its encryption slot as a signing slot.
        const fileId = String(record.file_id ?? "unknown");
        const usage = encrypt ? "Encrypt" : fileId === "3002" ? "Unknown" : "Sign";
        valid.push({ certificateDer, certificate, fileId, usage, fingerprint: fingerprint(certificateDer) });
      } catch { /* Invalid public records are excluded, never used as a fallback. */ }
    }
    const deviceId = String(device.device_id ?? "");
    const deviceSn = String(device.device_sn ?? "");
    const setHash = fingerprint(Buffer.from(valid.map((r) => r.fingerprint).sort().join(":")));
    // Attachment ID changes on replug; the full certificate set binds sign and
    // decrypt certificates to the same token without using a global PIN lease.
    const binding = `${deviceId || deviceSn || "legacy-single-device"}:${setHash}`;
    for (const record of valid) records.push({ ...record, device, deviceId, deviceSn,
      deviceType: Number(device.device_type ?? 47), binding });
  }
  return { devices, records };
}

function selectorFilter(selector = {}) {
  if (selector === null || typeof selector !== "object" || Array.isArray(selector)) throw new Error("证书选择参数无效");
  const tests = [];
  const inValidity = (r) => {
    const now = Date.now();
    return Date.parse(r.certificate.validFrom) <= now && now <= Date.parse(r.certificate.validTo);
  };
  const hasPrivateContainer = (r) => {
    try { assertPrivateKeyContainer(r, r.usage); return r.usage === "Sign" || r.usage === "Encrypt"; }
    catch { return false; }
  };
  if (selector.type !== undefined && String(selector.type).toLowerCase() !== "device") {
    // Legacy NETCA Certificate.Select serializes its device selector into type.
    // Parse data only; never evaluate the caller's expression or ignore filters.
    let legacy;
    try {
      const text = String(selector.type);
      // The portal also sends an escaped object without enclosing string
      // quotes, e.g. {\"Method\":\"device\"}. Decode exactly one string layer
      // with JSON's parser, then require the same bounded object schema.
      if (/^\s*\{\s*\\"/.test(text)) legacy = JSON.parse(JSON.parse('"' + text + '"'));
      else legacy = JSON.parse(text);
    } catch { throw new Error("当前仅支持设备证书选择"); }
    if (!legacy || typeof legacy !== "object" || Array.isArray(legacy) ||
        Object.keys(legacy).some((key) => !["UIFlag", "InValidity", "Type", "Method", "Value"].includes(key)) ||
        legacy.Method !== "device" || legacy.Value !== "any" ||
        (legacy.UIFlag !== undefined && legacy.UIFlag !== "default") ||
        (legacy.InValidity !== undefined && typeof legacy.InValidity !== "boolean") ||
        (legacy.Type !== undefined && !["signature", "encrypt"].includes(legacy.Type))) {
      throw new Error("不支持的设备证书选择规则");
    }
    if (legacy.InValidity === true) tests.push(inValidity);
    if (legacy.Type !== undefined) tests.push((r) => r.usage === (legacy.Type === "signature" ? "Sign" : "Encrypt"));
  }
  const fields = {
    invalidity: inValidity,
    checkprivkey: hasPrivateContainer,
    certtype: (r) => r.usage,
    devicesn: (r) => r.deviceSn,
    devicetype: (r) => String(r.deviceType),
    deviceid: (r) => r.deviceId,
    thumbprint: (r) => compactHex(r.certificate.fingerprint),
    thumbprint256: (r) => r.fingerprint,
    serialnumber: (r) => r.certificate.serialNumber,
    subjectcn: (r) => r.certificate.toLegacyObject().subject?.CN ?? "",
    issuercn: (r) => r.certificate.toLegacyObject().issuer?.CN ?? "",
  };
  for (const key of ["deviceId", "deviceSn", "deviceType", "fileId", "Thumbprint256"]) {
    if (selector[key] !== undefined) {
      const read = key === "fileId" ? (r) => r.fileId : fields[key.toLowerCase()];
      const target = key === "Thumbprint256" ? compactHex(selector[key]) : String(selector[key]);
      tests.push((r) => String(read(r)) === target);
    }
  }
  if (selector.encode || selector.certCode) {
    const expected = fingerprint(decodeCertificateEncode(selector.encode || selector.certCode));
    tests.push((r) => r.fingerprint === expected);
  }
  if (selector.condition !== undefined && typeof selector.condition !== "string") throw new Error("证书筛选条件无效");
  const condition = selector.condition?.trim();
  if (condition) {
    // Deliberately bounded grammar. Unknown expressions must fail rather than
    // selecting the first certificate under a caller's unfulfilled condition.
    const token = /\s*([A-Za-z][A-Za-z0-9]*)\s*([=~])\s*(?:'([^']*)'|"([^"]*)"|([0-9]+))\s*/y;
    let offset = 0;
    while (offset < condition.length) {
      token.lastIndex = offset;
      const match = token.exec(condition);
      if (!match || !fields[match[1].toLowerCase()]) throw new Error("不支持的证书筛选条件");
      const field = match[1].toLowerCase();
      const operator = match[2];
      if (operator === "~" && field !== "issuercn") throw new Error("不支持的证书筛选条件");
      let target = match[3] ?? match[4] ?? match[5];
      if (field === "invalidity" || field === "checkprivkey") {
        if (!/^(true|false)$/i.test(target)) throw new Error("证书布尔筛选条件无效");
        target = target.toLowerCase() === "true";
      }
      if (field.startsWith("thumbprint")) target = compactHex(target);
      if (field === "certtype" && target.toLowerCase() === "signature") target = "Sign";
      tests.push((r) => operator === "~" ? String(fields[field](r)).toLowerCase().includes(target.toLowerCase())
        : typeof target === "boolean" ? fields[field](r) === target : field === "certtype"
        ? fields[field](r).toLowerCase() === target.toLowerCase()
        : String(fields[field](r)) === target);
      offset = token.lastIndex;
      if (offset === condition.length) break;
      const and = /^(?:AND\s+|&&\s*)/i.exec(condition.slice(offset));
      if (!and) throw new Error("不支持的证书筛选条件");
      offset += and[0].length;
      if (offset === condition.length) throw new Error("证书筛选条件不完整");
    }
  }
  return (r) => tests.every((test) => test(r));
}

function matchingCertificates(probe, selector = {}, purpose) {
  const filter = selectorFilter(selector);
  return certificateInventory(probe).records.filter((r) => (!purpose || r.usage === purpose) && filter(r));
}
function selectCertificate(probe, selector = {}, purpose, accept = () => true, preferredDeviceId = null) {
  let records = matchingCertificates(probe, selector, purpose).filter(accept);
  if (records.length > 1 && preferredDeviceId !== null) {
    const preferred = records.filter((r) => r.deviceId === preferredDeviceId);
    if (preferred.length) records = preferred;
  }
  if (!records.length) throw new Error(purpose === "Encrypt" ? "USBKey 中未找到匹配的有效加密证书" : "USBKey 中未找到匹配的有效签名证书");
  if (records.length > 1) throw new Error("匹配到多张证书，请指定设备或证书");
  return records[0];
}
function publicCertificateRecord(record) {
  const result = { ...certificateObject(record.certificateDer),
    deviceType: record.deviceType, deviceSn: record.deviceSn, deviceId: record.deviceId,
    sn: record.deviceSn, type: record.deviceType,
    fileId: record.fileId, certType: record.usage };
  if (Number.isInteger(record.device.retries) && record.device.retries >= 0) result.deviceRetryNum = record.device.retries;
  return result;
}
function assertPrivateKeyContainer(record, purpose) {
  if (record.certificate.publicKey.asymmetricKeyType !== "rsa" ||
      record.certificate.publicKey.asymmetricKeyDetails?.modulusLength !== 2048) {
    throw new Error("USBKey 私钥操作当前仅支持 RSA-2048");
  }
  const expected = purpose === "Sign" ? "3001" : "3002";
  if (record.fileId !== expected || (purpose === "Encrypt" &&
      !String(record.device.container_diagnostics).startsWith("0:1240010101300109023002"))) {
    throw new Error("USBKey 私钥容器不受支持");
  }
  if (!record.deviceId) throw new Error("USBKey 缺少设备绑定标识，请更新探测助手");
}
export { certificateObject, certificateInventory, matchingCertificates, selectCertificate,
  publicCertificateRecord, assertPrivateKeyContainer };
