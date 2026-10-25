use super::crypto;
use anyhow::{Result, bail, ensure};
use chrono::{NaiveDateTime, SecondsFormat};
use openssl::{
    asn1::Asn1Time,
    pkey::Id,
    x509::{X509, X509NameRef},
};
use regex::Regex;
use serde_json::{Value, json};
use std::sync::OnceLock;

// Compiled once per process: `matching` runs on every certificate listing and
// signing request.
fn token_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"^\s*([A-Za-z][A-Za-z0-9]*)\s*([=~])\s*(?:'([^']*)'|"([^"]*)"|([0-9]+))\s*"#)
            .unwrap()
    })
}

fn and_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i)^(?:AND\s+|&&\s*)").unwrap())
}

pub fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        _ => value.to_string(),
    }
}
pub fn number(value: &Value) -> Option<i64> {
    match value {
        Value::Null => Some(0),
        Value::Bool(v) => Some(i64::from(*v)),
        Value::String(s) if s.trim().is_empty() => Some(0),
        _ => value
            .as_f64()
            .or_else(|| value.as_str()?.trim().parse::<f64>().ok())
            .filter(|n| {
                n.is_finite() && n.fract() == 0.0 && *n >= i64::MIN as f64 && *n < i64::MAX as f64
            })
            .map(|n| n as i64),
    }
}
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        _ => true,
    }
}
fn name_field(value: &Value) -> String {
    if let Some(array) = value.as_array() {
        array.iter().map(text).collect::<Vec<_>>().join(",")
    } else {
        value.as_str().unwrap_or("").into()
    }
}
fn compact(value: &Value) -> String {
    text(value)
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_uppercase()
}
fn names(name: &X509NameRef) -> Value {
    let mut out = json!({});
    for e in name.entries() {
        let key = e.object().nid().short_name().unwrap_or("unknown");
        let key = if key == "emailAddress" {
            "emailAddress"
        } else {
            key
        };
        let value = e.data().to_string().unwrap_or_default();
        match out.get_mut(key) {
            None => out[key] = json!(value),
            Some(Value::Array(values)) => values.push(json!(value)),
            Some(old) => {
                let first = old.take();
                *old = json!([first, value]);
            }
        }
    }
    out
}
fn name_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("unknown"),
                e.data().to_string().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn date(time: &openssl::asn1::Asn1TimeRef) -> Result<String> {
    Ok(
        NaiveDateTime::parse_from_str(&time.to_string(), "%b %e %H:%M:%S %Y GMT")?
            .and_utc()
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}
#[derive(Clone)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub x509: X509,
    pub object: Value,
    pub usage: Option<u16>,
    pub fingerprint: String,
}
impl Certificate {
    pub fn new(der: Vec<u8>) -> Result<Self> {
        let x509 = X509::from_der(&der).map_err(|_| anyhow::anyhow!("证书 DER 格式无效"))?;
        // Reject concatenated/trailing certificate data just as the DER profile does.
        let (_, rest) = crypto::read(&der)?;
        ensure!(rest.is_empty(), "证书 DER 格式无效");
        let public = x509.public_key()?;
        let usage = crypto::key_usage(&der)?;
        let fingerprint = crypto::hex(&crypto::digest(&der, false));
        let encoded = crypto::b64(&der);
        let mut object = json!({"certCode":encoded,"certEncode":encoded,"encode":encoded,
            "subject":name_string(x509.subject_name()),"issuer":name_string(x509.issuer_name()),
            "serialNumber":x509.serial_number().to_bn()?.to_hex_str()?.to_string(),
            "Thumbprint":crypto::hex(&crypto::digest(&der,true)),"Thumbprint256":fingerprint,
            "validFromDate":date(x509.not_before())?,"validToDate":date(x509.not_after())?,
            "publicKeyAlgorithmName":if public.id() == Id::RSA {"rsa"} else if public.id() == Id::EC {"ec"} else {"unknown"}});
        if public.id() == Id::RSA {
            object["publicKeyAlgorithm"] = json!(1);
            object["publicKeyType"] = json!(1);
            object["publicKeyBits"] = json!(public.bits());
        }
        if let Some(usage) = usage {
            object["keyUsage"] = json!(usage);
        }
        for (prefix, source) in [
            ("subject", names(x509.subject_name())),
            ("issuer", names(x509.issuer_name())),
        ] {
            for key in ["CN", "O", "OU", "L", "ST", "C", "emailAddress"] {
                if let Some(value) = source.get(key) {
                    object[format!(
                        "{prefix}{}",
                        if key == "emailAddress" { "Email" } else { key }
                    )] = value.clone();
                }
            }
        }
        Ok(Self {
            der,
            x509,
            object,
            usage,
            fingerprint,
        })
    }
    pub fn valid(&self) -> bool {
        Asn1Time::days_from_now(0)
            .is_ok_and(|now| self.x509.not_before() <= now && self.x509.not_after() >= now)
    }
    pub fn encryption(&self) -> bool {
        self.usage.unwrap_or(0) & 0x1c != 0
    }
}
#[derive(Clone)]
pub struct Record {
    pub cert: Certificate,
    pub device: Value,
    pub device_id: String,
    pub device_sn: String,
    pub file_id: String,
    pub usage: &'static str,
    pub binding: String,
}
impl Record {
    pub fn public(&self) -> Value {
        let mut out = self.cert.object.clone();
        for (key, value) in [
            (
                "deviceType",
                self.device.get("device_type").cloned().unwrap_or(json!(47)),
            ),
            (
                "type",
                self.device.get("device_type").cloned().unwrap_or(json!(47)),
            ),
            ("deviceId", json!(self.device_id)),
            ("deviceSn", json!(self.device_sn)),
            ("sn", json!(self.device_sn)),
            ("fileId", json!(self.file_id)),
            ("certType", json!(self.usage)),
        ] {
            out[key] = value;
        }
        if let Some(retries) = self.device["retries"].as_u64() {
            out["deviceRetryNum"] = json!(retries);
        }
        out
    }
    pub fn private_container(&self, purpose: &str) -> Result<()> {
        let public = self.cert.x509.public_key()?;
        ensure!(
            public.id() == Id::RSA && public.bits() == 2048,
            "USBKey 私钥操作当前仅支持 RSA-2048"
        );
        ensure!(
            self.file_id == if purpose == "Sign" { "3001" } else { "3002" },
            "USBKey 私钥容器不受支持"
        );
        if purpose == "Encrypt" {
            ensure!(
                self.device["container_diagnostics"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("0:1240010101300109023002"),
                "USBKey 私钥容器不受支持"
            );
        }
        ensure!(
            !self.device_id.is_empty(),
            "USBKey 缺少设备绑定标识，请更新探测助手"
        );
        Ok(())
    }
}
pub fn inventory(devices: &[Value]) -> Vec<Record> {
    let mut records = Vec::new();
    for device in devices {
        let candidates = device["certificates"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| {
                device
                    .get("certificate_base64")
                    .map(|e| vec![json!({"file_id":device["certificate_file_id"],"encode":e})])
                    .unwrap_or_default()
            });
        let mut valid = Vec::new();
        for candidate in candidates {
            if let Ok(cert) = crypto::cert_decode(candidate["encode"].as_str().unwrap_or(""))
                .and_then(Certificate::new)
            {
                let file_id = candidate["file_id"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned();
                let usage = if cert.encryption() {
                    "Encrypt"
                } else if file_id == "3002" {
                    "Unknown"
                } else {
                    "Sign"
                };
                valid.push((cert, file_id, usage));
            }
        }
        let mut hashes: Vec<_> = valid.iter().map(|v| v.0.fingerprint.clone()).collect();
        hashes.sort();
        let device_id = device["device_id"].as_str().unwrap_or("").to_owned();
        let device_sn = device["device_sn"].as_str().unwrap_or("").to_owned();
        let identity = if !device_id.is_empty() {
            device_id.as_str()
        } else if !device_sn.is_empty() {
            device_sn.as_str()
        } else {
            "legacy-single-device"
        };
        let binding = format!(
            "{}:{}",
            identity,
            crypto::hex(&crypto::digest(hashes.join(":").as_bytes(), false))
        );
        for (cert, file_id, usage) in valid {
            records.push(Record {
                cert,
                file_id,
                usage,
                device: device.clone(),
                device_id: device_id.clone(),
                device_sn: device_sn.clone(),
                binding: binding.clone(),
            });
        }
    }
    records
}

struct Rule {
    field: String,
    target: String,
    contains: bool,
}
fn field(record: &Record, name: &str) -> Result<String> {
    Ok(match name {
        "invalidity" => record.cert.valid().to_string(),
        "checkprivkey" => (record.private_container(record.usage).is_ok()
            && record.usage != "Unknown")
            .to_string(),
        "certtype" => record.usage.into(),
        "deviceid" => record.device_id.clone(),
        "devicesn" => record.device_sn.clone(),
        "devicetype" => record
            .device
            .get("device_type")
            .map(text)
            .unwrap_or("47".into()),
        "fileid" => record.file_id.clone(),
        "thumbprint" => text(&record.cert.object["Thumbprint"]),
        "thumbprint256" => record.cert.fingerprint.clone(),
        "serialnumber" => text(&record.cert.object["serialNumber"]),
        "subjectcn" => name_field(&record.cert.object["subjectCN"]),
        "issuercn" => name_field(&record.cert.object["issuerCN"]),
        _ => bail!("不支持的证书筛选条件"),
    })
}
pub fn matching(
    records: &[Record],
    selector: &Value,
    purpose: Option<&str>,
) -> Result<Vec<Record>> {
    ensure!(
        selector.is_object() || selector.is_null(),
        "证书选择参数无效"
    );
    let mut rules = Vec::new();
    let mut require_valid = false;
    if let Some(value) = selector.get("type") {
        ensure!(value.is_string(), "当前仅支持设备证书选择");
        let raw = text(value);
        if !raw.eq_ignore_ascii_case("device") {
            let raw = if raw
                .trim_start()
                .strip_prefix('{')
                .is_some_and(|s| s.trim_start().starts_with("\\\""))
            {
                serde_json::from_str::<String>(&format!("\"{raw}\""))?
            } else {
                raw
            };
            let legacy: Value = serde_json::from_str(&raw)
                .map_err(|_| anyhow::anyhow!("当前仅支持设备证书选择"))?;
            let map = legacy
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("不支持的设备证书选择规则"))?;
            ensure!(
                map.keys()
                    .all(|k| ["UIFlag", "InValidity", "Type", "Method", "Value"]
                        .contains(&k.as_str()))
                    && legacy["Method"] == "device"
                    && legacy["Value"] == "any",
                "不支持的设备证书选择规则"
            );
            ensure!(
                legacy.get("UIFlag").is_none_or(|v| v == "default")
                    && legacy.get("InValidity").is_none_or(Value::is_boolean),
                "不支持的设备证书选择规则"
            );
            if let Some(kind) = legacy.get("Type") {
                ensure!(
                    kind == "signature" || kind == "encrypt",
                    "不支持的设备证书选择规则"
                );
                rules.push(Rule {
                    field: "certtype".into(),
                    target: if kind == "signature" {
                        "Sign"
                    } else {
                        "Encrypt"
                    }
                    .into(),
                    contains: false,
                });
            }
            require_valid = legacy["InValidity"] == true;
        }
    }
    for key in [
        "deviceId",
        "deviceSn",
        "deviceType",
        "fileId",
        "Thumbprint256",
    ] {
        if let Some(value) = selector.get(key) {
            rules.push(Rule {
                field: key.to_lowercase(),
                target: if key == "Thumbprint256" {
                    compact(value)
                } else {
                    text(value)
                },
                contains: false,
            });
        }
    }
    let fingerprint = selector
        .get("encode")
        .filter(|v| truthy(v))
        .or_else(|| selector.get("certCode").filter(|v| truthy(v)))
        .map(|v| {
            crypto::cert_decode(
                v.as_str()
                    .ok_or_else(|| anyhow::anyhow!("加密证书编码无效"))?,
            )
            .map(|der| crypto::hex(&crypto::digest(&der, false)))
        })
        .transpose()?;
    ensure!(
        selector.get("condition").is_none_or(Value::is_string),
        "证书筛选条件无效"
    );
    let mut condition = selector["condition"].as_str().unwrap_or("").trim();
    let token = token_pattern();
    let and = and_pattern();
    while !condition.is_empty() {
        let captures = token
            .captures(condition)
            .ok_or_else(|| anyhow::anyhow!("不支持的证书筛选条件"))?;
        let field = captures[1].to_lowercase();
        let contains = &captures[2] == "~";
        ensure!(
            [
                "invalidity",
                "checkprivkey",
                "certtype",
                "devicesn",
                "devicetype",
                "deviceid",
                "thumbprint",
                "thumbprint256",
                "serialnumber",
                "subjectcn",
                "issuercn"
            ]
            .contains(&field.as_str())
                && (!contains || field == "issuercn"),
            "不支持的证书筛选条件"
        );
        let mut target = captures
            .get(3)
            .or(captures.get(4))
            .or(captures.get(5))
            .unwrap()
            .as_str()
            .to_owned();
        if field == "invalidity" || field == "checkprivkey" {
            ensure!(
                target.eq_ignore_ascii_case("true") || target.eq_ignore_ascii_case("false"),
                "证书布尔筛选条件无效"
            );
            target.make_ascii_lowercase();
        }
        if field.starts_with("thumbprint") {
            target = compact(&json!(target));
        }
        if field == "certtype" && target.eq_ignore_ascii_case("signature") {
            target = "Sign".into();
        }
        rules.push(Rule {
            field,
            target,
            contains,
        });
        condition = &condition[captures.get(0).unwrap().end()..];
        if condition.is_empty() {
            break;
        }
        let separator = and
            .find(condition)
            .ok_or_else(|| anyhow::anyhow!("不支持的证书筛选条件"))?;
        condition = &condition[separator.end()..];
        ensure!(!condition.is_empty(), "证书筛选条件不完整");
    }
    let mut result = Vec::new();
    for record in records {
        if purpose.is_some_and(|p| record.usage != p)
            || (require_valid && !record.cert.valid())
            || fingerprint
                .as_ref()
                .is_some_and(|f| record.cert.fingerprint != *f)
        {
            continue;
        }
        let mut matches = true;
        for rule in &rules {
            let value = field(record, &rule.field)?;
            matches &= if rule.contains {
                value.to_lowercase().contains(&rule.target.to_lowercase())
            } else if rule.field == "certtype" {
                value.eq_ignore_ascii_case(&rule.target)
            } else {
                value == rule.target
            };
        }
        if matches {
            result.push(record.clone());
        }
    }
    Ok(result)
}
pub fn choose(mut records: Vec<Record>, purpose: &str, preferred: Option<&str>) -> Result<Record> {
    if records.len() > 1
        && let Some(preferred) = preferred
    {
        let selected: Vec<_> = records
            .iter()
            .filter(|r| r.device_id == preferred)
            .cloned()
            .collect();
        if !selected.is_empty() {
            records = selected;
        }
    }
    ensure!(
        !records.is_empty(),
        "{}",
        if purpose == "Encrypt" {
            "USBKey 中未找到匹配的有效加密证书"
        } else {
            "USBKey 中未找到匹配的有效签名证书"
        }
    );
    ensure!(records.len() == 1, "匹配到多张证书，请指定设备或证书");
    Ok(records.remove(0))
}
