import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, mkdirSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

const port = Number(option("--port", "10443"));
const certificatePath = resolve(option(
  "--cert",
  resolve(projectRoot, ".local/tls/localhost.crt"),
));
const privateKeyPath = resolve(option(
  "--key",
  resolve(projectRoot, ".local/tls/localhost.key"),
));
const probePath = resolve(option(
  "--probe",
  resolve(projectRoot, "build/ft3000gm-hid-probe"),
));
const signerPath = resolve(option(
  "--signer",
  resolve(projectRoot, "build/ft3000gm-signer"),
));
const trustStorePath = resolve(option(
  "--trust-store",
  resolve(
    projectRoot,
    "work/gdpower-enveloped-adapter/extracted-crypto-20260907/" +
      "commonappdata/NETCA/certs/trust",
  ),
));
const logPath = resolve(option(
  "--log",
  resolve(projectRoot, ".local/logs/bridge.log"),
));
const parentPid = Number(option("--parent-pid", "0"));
const allowedOrigins = new Set(["https://pm.gd.csg.cn"]);
const websocketProtocol = "crypto-jsonrpc-protocol";
const bridgeVersion = "1.1.15";

function initializeAuditLog() {
  mkdirSync(dirname(logPath), { recursive: true });
  try {
    chmodSync(logPath, 0o600);
  } catch {
    writeFileSync(logPath, "", { mode: 0o600 });
  }
}
let auditInitialized = false;

// Explicit local one-shot diagnostic. Never capture credentials, encoded
// certificates, or the rest of an RPC request. Normal audit stays redacted.
function captureRejectedCertificateSelector(selector) {
  const marker = resolve(dirname(logPath), ".capture-certificate-selector-once");
  if (!existsSync(marker)) return;
  try {
    const rules = {};
    for (const field of ["type", "condition"]) {
      const value = selector?.[field];
      rules[field] = typeof value === "string" && value.length <= 4096
        ? value : { type: typeof value, length: value?.length };
    }
    const target = resolve(dirname(logPath), "rejected-certificate-selector.json");
    writeFileSync(target, JSON.stringify({ timestamp: new Date().toISOString(), rules }, null, 2) + "\n", { mode: 0o600 });
    chmodSync(target, 0o600);
  } finally {
    try { unlinkSync(marker); } catch { /* one-shot marker may already be gone */ }
  }
}

function audit(event, details = {}) {
  if (!auditInitialized) { initializeAuditLog(); auditInitialized = true; }
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    ...details,
  });
  console.log(entry);
  appendFileSync(logPath, `${entry}\n`, { mode: 0o600 });
}

function summarize(value, key = "") {
  if (/pwd|pass|captcha|verify|certcode|certencode|signature/i.test(key)) {
    return "<redacted>";
  }
  if (value === null) return null;
  if (Array.isArray(value)) {
    return { type: "array", length: value.length };
  }
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        summarize(childValue, childKey),
      ]),
    );
  }
  if (typeof value === "string") {
    return key === "algo" ? value : `<string length=${value.length}>`;
  }
  return value;
}


export {
  execFileAsync, port, certificatePath, privateKeyPath, probePath, signerPath,
  trustStorePath, logPath, parentPid, allowedOrigins, websocketProtocol,
  bridgeVersion, audit, summarize, captureRejectedCertificateSelector,
};
