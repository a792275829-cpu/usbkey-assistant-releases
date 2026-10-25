import { certificateSupportsEncryption, decodeCertificateEncode } from "./cms.mjs";
import { X509Certificate } from "node:crypto";
import { deviceSelection } from "./device-selection.mjs";
import { spawn } from "node:child_process";
import { execFileAsync, probePath, signerPath, audit } from "./runtime.mjs";
import { nativeAuthToken } from "./native-auth-context.mjs";

// Installed only by the private Rust worker. The legacy server retains its
// existing subprocess path; failure of the native runner never triggers fallback.
let deviceProcessRunner = null;
function setDeviceProcessRunner(runner) { deviceProcessRunner = runner; }
async function readHelper(tool, args, maxBuffer = 1024 * 1024) {
  if (!deviceProcessRunner) return execFileAsync(tool === "probe" ? probePath : signerPath, args,
    { encoding: "utf8", timeout: 10000, maxBuffer });
  const result = await deviceProcessRunner({ tool, args, input: "" });
  if (result.code !== 0) throw new Error("USBKey 硬件读取失败");
  return { stdout: result.stdout };
}

async function readDeviceInventory() {
  const { stdout } = await readHelper("probe", ["--list-devices"]);
  const result = JSON.parse(stdout);
  if (!Array.isArray(result.devices) || result.devices.some((d) => !/^[0-9a-f]{1,16}$/i.test(d.device_id) || /^0+$/.test(d.device_id))) {
    throw new Error("设备枚举结果无效");
  }
  return [...new Map(result.devices.map((d) => [d.device_id, d])).values()]
    .sort((a, b) => a.device_id.localeCompare(b.device_id));
}
async function readPublicCertificate() {
  const inventory = await readDeviceInventory();
  const devices = [];
  for (const device of inventory) {
    try {
      const { stdout } = await readHelper("probe",
        ["--include-certificate", "--device-id", device.device_id]);
      const result = JSON.parse(stdout);
      if (!result.device_found || result.device_id !== device.device_id) throw new Error("设备已改变");
      devices.push({ ...result, device_id: device.device_id });
    } catch {
      // Keep the physical device in the inventory without inventing certificates.
      devices.push({ ...device, device_found: true, certificates: [], certificate_count: 0 });
    }
  }
  const first = devices[0] ?? {};
  return { ...first, device_found: devices.length > 0, devices,
    certificate_count: devices.reduce((n, d) => n + (d.certificates?.length ?? 0), 0) };
}

function signerFailure(result, decrypt, operation) {
  if (result.device_found === false) return new Error("未发现所选 USBKey");
  if (result.df_authenticated === false) return new Error("USBKey 应用目录认证失败");
  if (result.pin_verified === false) {
    const retries = Number.isInteger(result.retries) && result.retries >= 0 ? result.retries : -1;
    const error = new Error(`证书密码验证失败${retries >= 0 ? `，剩余尝试次数 ${retries}` : ""}`);
    const sw = String(result.verify_sw).toUpperCase();
    if (/^63C[0-9A-F]$/.test(sw) || sw === "6983") {
      error.code = "USBKEY_PIN_REJECTED";
      error.pinStatusWord = sw; error.retries = retries;
      // Bridge business-result mapping; retain raw status internally. No retry.
      error.netcaResult = sw === "6983" ? -81 : -5;
    }
    return error;
  }
  const error = new Error(decrypt ? "USBKey 解密失败" : "USBKey 签名失败");
  if (operation === "--decrypt-rsa-block-no-pin" && String(result.signature_sw).toUpperCase() === "6982") {
    error.code = "USBKEY_USER_AUTH_REQUIRED";
  }
  return error;
}

function runProtectedSigner(pin, digestInfo, operation = "--sign-digest-info", selected = {}) {
  const pinRequired = operation !== "--decrypt-rsa-block-no-pin";
  const args = [operation];
  if (selected.deviceId) {
    if (!/^[0-9a-f]{1,16}$/i.test(selected.deviceId)) return Promise.reject(new Error("设备标识无效"));
    args.push("--device-id", selected.deviceId);
  }
  if (pinRequired && (typeof pin !== "string" || pin.length === 0 ||
      pin.length > 64 || /[\r\n]/.test(pin))) {
    return Promise.reject(new Error("证书密码格式无效"));
  }
  if (deviceProcessRunner) {
    return deviceProcessRunner({ tool: "signer", args, authToken: nativeAuthToken(), input: pinRequired
      ? `${pin}\n${digestInfo.toString("base64")}\n` : `${digestInfo.toString("base64")}\n` })
      .then((result) => decodeSignerResult(result.stdout, result.code, result.stderrBytes,
        operation.startsWith("--decrypt-rsa-block"), operation));
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(signerPath, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: process.env.PATH },
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill("SIGKILL"), 15000);
    child.stdin.on("error", () => {}); // close/error carries the helper failure, including early device removal.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 1024 * 1024) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (stderr.length > 64 * 1024) child.kill("SIGKILL");
    });
    child.on("error", () => {
      clearTimeout(timeout);
      rejectPromise(new Error("无法启动 FT3000GM 签名助手"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      try { resolvePromise(decodeSignerResult(stdout, code, Buffer.byteLength(stderr),
        operation.startsWith("--decrypt-rsa-block"), operation)); }
      catch (error) { rejectPromise(error); }
    });
    child.stdin.end(pinRequired
      ? `${pin}\n${digestInfo.toString("base64")}\n`
      : `${digestInfo.toString("base64")}\n`);
  });
}

function decodeSignerResult(stdout, code, stderrBytes, decrypt, operation) {
  let result;
  try { result = JSON.parse(stdout); }
  catch { throw new Error("FT3000GM 签名助手返回无效结果"); }
  const output = decrypt ? result.rsa_block_base64 : result.signature_base64;
  if (code !== 0 || (decrypt ? result.decrypted : result.signed) !== true || typeof output !== "string") {
    audit("signer_failure", { exitCode: code, dfAuthenticated: result.df_authenticated,
      authStatusWord: result.auth_sw, pinVerified: result.pin_verified, pinStatusWord: result.verify_sw,
      retries: Number.isInteger(result.retries) ? result.retries : undefined,
      signatureStatusWord: result.signature_sw, stderrBytes });
    throw signerFailure(result, decrypt, operation);
  }
  return Buffer.from(output, "base64");
}


async function readDeviceStatus({ probeReader = readPublicCertificate, selection = deviceSelection,
  pinStatusReader = async (device) => {
    const args = device.device_id ? ["--pin-status", "--device-id", device.device_id] : ["--pin-status"];
    const { stdout } = await readHelper("signer", args, 65536);
    return JSON.parse(stdout);
  } } = {}) {
  const probe = await probeReader();
  if (Array.isArray(probe.devices)) {
    selection.reconcile(probe.devices);
    const devices = [];
    for (const device of probe.devices) {
      const summary = await readDeviceStatus({ probeReader: async () => ({ ...device, devices: undefined }), pinStatusReader, selection });
      devices.push({ service: "netca-ft3000gm", ...summary, deviceId: device.device_id, deviceType: device.device_type ?? 47 });
    }
    const selectedId = selection.current() ?? (devices.length === 1 ? devices[0].deviceId : null);
    const selected = devices.find((d) => d.deviceId === selectedId);
    return { deviceFound: devices.length > 0, certificateCount: probe.certificate_count,
      certificateFileId: selected?.certificateFileId ?? null,
      signingCertificateFileId: selected?.signingCertificateFileId ?? null,
      retries: selected?.retries ?? null, organization: selected?.organization ?? null,
      holder: selected?.holder ?? null, expiresAt: selected?.expiresAt ?? null,
      deviceCount: devices.length, selectedDeviceId: selectedId,
      requiresSelection: devices.length > 1 && !selected, devices };
  }
  if (probe.device_found === false) throw new Error("未发现可读取的 USBKey");
  const current = probe;
  const signing = current.certificates?.find((record) => {
    try { return !certificateSupportsEncryption(decodeCertificateEncode(record.encode)); }
    catch { return false; }
  });
  let organization = null;
  let holder = null;
  let expiresAt = null;
  const record = signing ?? current.certificates?.[0];
  if (record) {
    try {
      const certificate = new X509Certificate(decodeCertificateEncode(record.encode));
      const subject = certificate.toLegacyObject().subject;
      const text = (value) => typeof value === "string" ? value :
        Array.isArray(value) && value.every((part) => typeof part === "string") ? value.join(" / ") : null;
      organization = text(subject.O);
      holder = text(subject.CN);
      expiresAt = new Date(certificate.validTo).toISOString();
    } catch {
      // Leave unavailable fields empty rather than showing stale identity.
    }
  }
  let retries = null;
  try {
    const status = record ? await pinStatusReader(current) : null;
    retries = Number.isInteger(status?.retries) && status.retries >= 0 ? status.retries : null;
  } catch {
    audit("pin_status_unavailable", {});
  }
  return { deviceFound: true, certificateCount: probe.certificate_count,
    certificateFileId: current.certificate_file_ids?.split(";")[0] ?? current.certificate_file_id ?? "",
    signingCertificateFileId: signing?.file_id ?? null, retries, organization, holder, expiresAt };
}
export { readDeviceInventory, readPublicCertificate, runProtectedSigner, readDeviceStatus, signerFailure, setDeviceProcessRunner };
