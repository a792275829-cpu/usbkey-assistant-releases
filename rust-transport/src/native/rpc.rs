use super::{
    Client, Connection, Connections, VERSION,
    auth::{Auth, HardwareError},
    certificates::{self, Certificate, Record},
    crypto, failure, notify, success,
};
use anyhow::{Result, ensure};
use openssl::{hash::MessageDigest, rsa::Padding, sign::Verifier};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

// One website step (list, read attribute, sign) repeats the same enumeration.
// A short window collapses those probes without ever hiding a plug or unplug
// from a path the user is actively looking at.
const INVENTORY_TTL: Duration = Duration::from_millis(1000);

pub struct Core {
    client: Client,
    connections: Connections,
    selected: Option<String>,
    previous: Option<Vec<Value>>,
    inventory: Mutex<Option<(Instant, Vec<Value>)>>,
}
impl Core {
    pub fn new(client: Client, connections: Connections) -> Self {
        Self {
            client,
            connections,
            selected: None,
            previous: None,
            inventory: Mutex::default(),
        }
    }
    async fn invalidate(&self) -> Result<()> {
        self.client.state(json!({"operation":"invalidate"})).await?;
        Ok(())
    }
    fn inventory_cached(&self) -> Option<Vec<Value>> {
        self.inventory
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(at, _)| at.elapsed() < INVENTORY_TTL)
            .map(|(_, devices)| devices.clone())
    }
    fn forget_inventory(&self) {
        *self.inventory.lock().unwrap() = None;
    }
    async fn inventory(&self) -> Result<Vec<Value>> {
        if let Some(devices) = self.inventory_cached() {
            return Ok(devices);
        }
        self.inventory_fresh().await
    }
    async fn inventory_fresh(&self) -> Result<Vec<Value>> {
        self.forget_inventory();
        let result = self
            .client
            .helper("probe", &["--list-devices".into()], "", None)
            .await?;
        ensure!(result["code"] == 0, "USBKey 设备枚举失败");
        let data: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))?;
        let mut devices = BTreeMap::new();
        for device in data["devices"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("设备枚举结果无效"))?
        {
            let id = device["device_id"].as_str().unwrap_or("");
            ensure!(
                !id.is_empty()
                    && id.len() <= 16
                    && id.bytes().all(|b| b.is_ascii_hexdigit())
                    && u64::from_str_radix(id, 16).unwrap_or(0) > 0,
                "设备枚举结果无效"
            );
            devices.insert(id.to_owned(), device.clone());
        }
        let devices: Vec<Value> = devices.into_values().collect();
        *self.inventory.lock().unwrap() = Some((Instant::now(), devices.clone()));
        Ok(devices)
    }
    async fn reconcile(&mut self, devices: &[Value]) -> Result<()> {
        let next = self
            .selected
            .as_ref()
            .filter(|id| devices.iter().any(|d| d["device_id"] == id.as_str()))
            .cloned()
            .or_else(|| {
                devices
                    .first()
                    .and_then(|d| d["device_id"].as_str())
                    .map(String::from)
            });
        if next != self.selected {
            self.selected = next;
            self.invalidate().await?;
        }
        Ok(())
    }
    async fn devices(&self, refresh: bool) -> Result<Vec<Value>> {
        let inventory = match if refresh {
            self.inventory_fresh().await
        } else {
            self.inventory().await
        } {
            Ok(v) => v,
            Err(e) => {
                self.forget_inventory();
                self.invalidate().await?;
                return Err(e);
            }
        };
        let mut devices = Vec::new();
        for device in inventory {
            let id = device["device_id"].as_str().unwrap();
            let read = async {
                let result = self
                    .client
                    .helper(
                        "probe",
                        &[
                            "--include-certificate".into(),
                            "--device-id".into(),
                            id.into(),
                        ],
                        "",
                        None,
                    )
                    .await?;
                ensure!(result["code"] == 0, "设备读取失败");
                let value: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))?;
                ensure!(
                    value["device_found"] == true && value["device_id"] == id,
                    "设备已改变"
                );
                Ok::<_, anyhow::Error>(value)
            }
            .await;
            devices.push(read.unwrap_or_else(|_| {
                let mut d = device.clone();
                d["device_found"] = json!(true);
                d["certificates"] = json!([]);
                d["certificate_count"] = json!(0);
                d
            }));
        }
        Ok(devices)
    }
    async fn records(&self) -> Result<(Vec<Value>, Vec<Record>)> {
        let devices = self.devices(false).await?;
        let records = certificates::inventory(&devices);
        self.client.state(json!({"operation":"reconcile_bindings","values":records.iter().map(|r|r.binding.clone()).collect::<Vec<_>>()})).await?;
        Ok((devices, records))
    }
    pub async fn scan(&mut self) -> Result<()> {
        let devices = match self.inventory_fresh().await {
            Ok(d) => d,
            Err(e) => {
                self.forget_inventory();
                self.invalidate().await?;
                return Err(e);
            }
        };
        self.reconcile(&devices).await?;
        self.client.state(json!({"operation":"reconcile_devices","values":devices.iter().map(|d|d["device_id"].clone()).collect::<Vec<_>>()})).await?;
        if let Some(previous) = &self.previous {
            for old in previous {
                if !devices.iter().any(|d| d["device_id"] == old["device_id"]) {
                    notify(&self.client, &self.connections, old, true);
                }
            }
            for new in &devices {
                if !previous.iter().any(|d| d["device_id"] == new["device_id"]) {
                    notify(&self.client, &self.connections, new, false);
                }
            }
        }
        self.previous = Some(devices);
        Ok(())
    }
    pub async fn select(&mut self, id: &str) -> Result<Value> {
        let devices = self.inventory_fresh().await?;
        ensure!(
            devices.iter().any(|d| d["device_id"] == id),
            "所选 USBKey 已断开，请刷新设备列表"
        );
        if self.selected.as_deref() != Some(id) {
            self.invalidate().await?;
            self.selected = Some(id.into());
        }
        Ok(json!({"selectedDeviceId":id}))
    }
    pub async fn forget(&self) -> Result<()> {
        self.invalidate().await?;
        self.client.store("clear", "", None).await?;
        self.client.audit("pin_store_cleared", json!({}));
        Ok(())
    }
    pub async fn status(&mut self) -> Result<Value> {
        let devices = self.devices(true).await?;
        self.reconcile(&devices).await?;
        let records = certificates::inventory(&devices);
        let mut summaries = Vec::new();
        for device in &devices {
            let id = device["device_id"].as_str().unwrap();
            let own: Vec<_> = records.iter().filter(|r| r.device_id == id).collect();
            let signing = own.iter().find(|r| !r.cert.encryption()).copied();
            let record = signing.or(own.first().copied());
            let mut retries = Value::Null;
            if record.is_some()
                && let Ok(result) = self
                    .client
                    .helper(
                        "signer",
                        &["--pin-status".into(), "--device-id".into(), id.into()],
                        "",
                        None,
                    )
                    .await
                && result["code"] == 0
                && let Ok(value) =
                    serde_json::from_str::<Value>(result["stdout"].as_str().unwrap_or(""))
                && value["retries"].as_u64().is_some()
            {
                retries = value["retries"].clone();
            }
            let label = |key: &str| {
                record
                    .map(|r| r.cert.object[key].clone())
                    .filter(|v| !v.is_null())
                    .map(|v| {
                        if let Some(array) = v.as_array() {
                            json!(
                                array
                                    .iter()
                                    .map(certificates::text)
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            )
                        } else {
                            v
                        }
                    })
                    .unwrap_or(Value::Null)
            };
            let certificate_id = device["certificate_file_ids"]
                .as_str()
                .and_then(|s| s.split(';').next())
                .or(device["certificate_file_id"].as_str())
                .unwrap_or("");
            summaries.push(json!({"service":"netca-ft3000gm","deviceId":id,"deviceType":device.get("device_type").cloned().unwrap_or(json!(47)),"deviceFound":true,"certificateCount":device["certificate_count"],"certificateFileId":certificate_id,"signingCertificateFileId":signing.map(|r|r.file_id.clone()),"retries":retries,"organization":label("subjectO"),"holder":label("subjectCN"),"expiresAt":label("validToDate")}));
        }
        let selected = summaries
            .iter()
            .find(|d| d["deviceId"].as_str() == self.selected.as_deref());
        // `reconcile` selects the first device, so this only stays true if that
        // ever changes; kept because the page still reads the field.
        let mut out = json!({"service":"netca-ft3000gm","version":VERSION,"deviceFound":!devices.is_empty(),"certificateCount":devices.iter().filter_map(|d|d["certificate_count"].as_u64()).sum::<u64>(),"deviceCount":devices.len(),"selectedDeviceId":self.selected,"requiresSelection":devices.len()>1&&selected.is_none(),"devices":summaries});
        for key in [
            "certificateFileId",
            "signingCertificateFileId",
            "retries",
            "organization",
            "holder",
            "expiresAt",
        ] {
            out[key] = selected.map(|d| d[key].clone()).unwrap_or(Value::Null);
        }
        Ok(out)
    }
    pub async fn dispatch(
        &mut self,
        request: &Value,
        connection: Option<&(u64, Arc<Connection>)>,
    ) -> Value {
        let name = request["requestQuery"]["function"]
            .as_str()
            .unwrap_or("undefined");
        self.client.audit(
            "rpc_request",
            json!({"method":name,"requestId":request["requestId"]}),
        );
        let result = self
            .dispatch_operation(name, &request["requestQuery"]["param"], request, connection)
            .await;
        if result.is_err()
            && name == "GetCertStringAttribute"
            && certificates::number(&request["requestQuery"]["param"]["id"]) == Some(-1)
        {
            self.client
                .capture_selector(&request["requestQuery"]["param"]["cert"]);
        }
        let response = match result {
            Ok(value) => value,
            Err(error) => {
                if let Some(HardwareError::PinRejected { result, retries }) =
                    error.downcast_ref::<HardwareError>()
                {
                    success(request, json!({"result":result,"retrynum":retries}))
                } else {
                    failure(request, &error.to_string(), -11000)
                }
            }
        };
        self.client.audit("rpc_response",json!({"method":name,"requestId":request["requestId"],"status":response["responseResult"]["status"]}));
        response
    }
    async fn dispatch_operation(
        &mut self,
        name: &str,
        param: &Value,
        request: &Value,
        connection: Option<&(u64, Arc<Connection>)>,
    ) -> Result<Value> {
        let result = match name {
            "GetVersionInfo1" | "GetVersionInfo" | "GetClientVersionInfo" => {
                json!({"version":format!("macOS-ft3000gm-{VERSION}"),"clientVersion":format!("macOS-ft3000gm-{VERSION}")})
            }
            "IsInsertKey" => {
                let (devices, _) = self.records().await?;
                json!({"insertCount":devices.len(),"sn":devices.first().and_then(|d|d["device_sn"].as_str()).unwrap_or(""),"type":devices.first().and_then(|d|d.get("device_type")).cloned().unwrap_or(json!(47))})
            }
            "GetCertList" => {
                let kind = param.get("type").and_then(certificates::number);
                if param.get("type").is_some() {
                    ensure!(
                        kind.is_some_and(|k| [0, 1, 2].contains(&k)),
                        "证书列表类型无效"
                    );
                }
                let (devices, records) = self.records().await?;
                let list = certificates::matching(&records, &param["cert"], None)?
                    .into_iter()
                    .filter(|r| match kind {
                        Some(1) => r
                            .cert
                            .usage
                            .is_some_and(|u| u & 0x19c != 0 && u & !0x19c == 0),
                        Some(2) => r.cert.usage.is_some_and(|u| u & 3 != 0) && r.cert.valid(),
                        _ => true,
                    })
                    .map(|r| r.public())
                    .collect::<Vec<_>>();
                json!({"deviceCount":devices.len(),"certCount":list.len(),"certInfo":list,"certList":list,"certs":list})
            }
            "GetCertStringAttribute" => {
                if certificates::number(&param["id"]) != Some(-1) {
                    return Ok(failure(request, "当前仅支持获取公有证书编码", -11001));
                }
                let (_, records) = self.records().await?;
                let selector = &param["cert"];
                let purpose = if ["encode", "certCode", "condition"]
                    .iter()
                    .any(|k| selector[*k].as_str().is_some_and(|s| !s.is_empty()))
                {
                    None
                } else {
                    Some("Sign")
                };
                let record = certificates::choose(
                    certificates::matching(&records, selector, purpose)?,
                    "Sign",
                    self.selected.as_deref(),
                )?;
                json!({"certCode":crypto::b64(&record.cert.der),"certEncode":crypto::b64(&record.cert.der)})
            }
            "MonitorDevice" => {
                let Some((_, connection)) = connection else {
                    return Ok(failure(request, "设备监测需要 WebSocket 连接", -11001));
                };
                let delay = param
                    .get("delayTime")
                    .filter(|v| !v.is_null())
                    .map(|v| v.as_f64())
                    .unwrap_or(Some(0.0))
                    .ok_or_else(|| anyhow::anyhow!("设备通知延迟需为0到60秒"))?;
                ensure!(
                    delay.is_finite() && (0.0..=60.0).contains(&delay),
                    "设备通知延迟需为0到60秒"
                );
                // The periodic scan only runs while a subscription exists, so the
                // first subscriber establishes the baseline it will diff against.
                if self.previous.is_none() {
                    let _ = self.scan().await;
                }
                connection.generation.fetch_add(1, Ordering::Relaxed);
                *connection.subscription.lock().unwrap() = Some((request.clone(), delay));
                json!({})
            }
            "ClearPwdCache" => {
                self.client
                    .state(json!({"operation":"clear_cached"}))
                    .await?;
                json!({"result":1})
            }
            "SignedDataSign" => self.sign(param).await?,
            "EnvelopedDataEncrypt" => self.encrypt(param).await?,
            "EnvelopedDataDecrypt" => self.decrypt(param).await?,
            _ => {
                return Ok(failure(
                    request,
                    &format!("macOS 桥暂不支持 {name}"),
                    -11001,
                ));
            }
        };
        Ok(success(request, result))
    }
    async fn encrypt(&self, param: &Value) -> Result<Value> {
        let raw = param
            .get("algo")
            .filter(|v| !v.is_null())
            .map(certificates::number)
            .unwrap_or(Some(4))
            .ok_or_else(|| anyhow::anyhow!("加密算法无效"))?;
        let algo = if raw <= 0 { 4 } else { raw };
        ensure!(
            [4, 6].contains(&algo),
            "当前仅支持网站要求的 AES-CBC EnvelopedData 算法"
        );
        let content = crypto::decode(
            param["data"]["text"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("待加密文本格式无效"))?,
        )?;
        ensure!(content.len() <= 1024 * 1024, "待加密文本过长");
        let cert = if let Some(encoded) = param["cert"]["encode"].as_str().filter(|s| !s.is_empty())
        {
            Certificate::new(crypto::cert_decode(encoded)?)?
        } else {
            let (_, records) = self.records().await?;
            certificates::choose(
                certificates::matching(&records, &param["cert"], Some("Encrypt"))?,
                "Encrypt",
                self.selected.as_deref(),
            )?
            .cert
        };
        let encoded = crypto::b64(&crypto::envelop(
            &cert.x509,
            &content,
            if algo == 4 { 128 } else { 256 },
        )?);
        self.client.audit("enveloped_data_created",json!({"algorithm":if algo==4{"AES-128-CBC"}else{"AES-256-CBC"},"contentBytes":content.len()}));
        Ok(
            json!({"result":1,"encData":encoded,"envelopedData":encoded,"envelopedDataEncode":encoded,"cipherText":encoded,"value":encoded,"encryptValue":encoded,"encryptValueType":"base64","certObject":cert.object}),
        )
    }
    async fn sign(&self, param: &Value) -> Result<Value> {
        let native = param.get("algo").is_none_or(Value::is_null);
        let algo = if native {
            2
        } else {
            certificates::number(&param["algo"]).unwrap_or(0)
        };
        ensure!(
            [2, 4].contains(&algo),
            "当前仅支持网站要求的 SHA1withRSA/SHA256withRSA 算法"
        );
        ensure!(
            certificates::number(&param["detached"]) == Some(1),
            "当前仅支持分离式 SignedData 签名"
        );
        let text = param["data"]["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("待签名文本格式无效"))?;
        ensure!(!text.is_empty(), "待签名文本为空");
        // Compatibility profile, not a feature gap: every value the site sends
        // (0-3) is accepted, but the SignedData always carries exactly one
        // certificate — the leaf — in the `[0]` field. That is what the captured
        // traffic and the previous adapter produced, and `test_native_backend`
        // asserts the bytes stay identical. Adding real chain inclusion here
        // would change the encoding the site receives.
        let include = param
            .get("includeCertOption")
            .filter(|v| !v.is_null())
            .map(certificates::number)
            .unwrap_or(Some(2));
        ensure!(
            include.is_some_and(|i| [0, 1, 2, 3].contains(&i)),
            "网站请求了不受支持的证书链包含选项"
        );
        let (_, records) = self.records().await?;
        let record = certificates::choose(
            certificates::matching(&records, &param["cert"], Some("Sign"))?,
            "Sign",
            self.selected.as_deref(),
        )?;
        record.private_container("Sign")?;
        let content = crypto::decode(text)?;
        let sha1 = algo == 2;
        if param["clearPwdCache"] == true {
            self.client
                .state(json!({"operation":"clear_cached"}))
                .await?;
        }
        let explicit = param["certPwd"].as_str().filter(|s| !s.is_empty());
        ensure!(
            param.get("certPwd").is_none_or(|v| v.is_string()),
            "证书密码格式无效"
        );
        let mut auth =
            Auth::new(self.client.clone(), record.binding.clone(), explicit, false).await?;
        let result=async {
            let signature=auth.hardware(&record.device_id,&crypto::digest_info(&content,sha1),false).await?;
            let public=record.cert.x509.public_key()?;let mut verifier=Verifier::new(if sha1{MessageDigest::sha1()}else{MessageDigest::sha256()},&public)?;verifier.set_rsa_padding(Padding::PKCS1)?;verifier.update(&content)?;ensure!(verifier.verify(&signature)?,"USBKey 返回的 RSA 签名未通过公钥自检");
            let signed=crypto::b64(&crypto::signed(&record.cert.der,&signature,sha1,native)?);
            auth.finish().await?;
            self.client.audit("signed_data_created",json!({"algorithm":if sha1{"SHA1withRSA"}else{"SHA256withRSA"},"contentBytes":content.len(),"signatureBytes":signature.len(),"includedCertificateCount":1,"signedAttributeProfile":"none"}));
            Ok::<_,anyhow::Error>(json!({"result":1,"signCert":crypto::b64(&record.cert.der),"signedData":signed,"signedDataEncode":signed,"signValue":signed,"value":signed,"certObject":record.public()}))
        }.await;
        if result.is_err() {
            auth.fail().await;
        }
        result
    }
    async fn decrypt(&self, param: &Value) -> Result<Value> {
        ensure!(
            !certificates::truthy(&param["savefileName"]),
            "当前解密接口仅支持页面内返回数据"
        );
        let env = crypto::parse_envelope(
            param["encData"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("数字信封格式无效"))?,
        )?;
        let (_, records) = self.records().await?;
        let candidates = certificates::matching(&records, &param["cert"], Some("Encrypt"))?;
        let matches = |record: &Record| -> Option<usize> {
            let ski = crypto::ski(&record.cert.x509).ok()?;
            let issuer = crypto::issuer_serial(&record.cert.der).ok()?;
            env.recipients.iter().position(|r| {
                r.ski
                    .as_ref()
                    .map(|s| s == &ski)
                    .unwrap_or_else(|| r.issuer_serial.as_ref() == Some(&issuer))
            })
        };
        let record = certificates::choose(
            candidates
                .into_iter()
                .filter(|r| matches(r).is_some())
                .collect(),
            "Encrypt",
            self.selected.as_deref(),
        )?;
        record.private_container("Encrypt")?;
        let recipient = &env.recipients[matches(&record).unwrap()];
        ensure!(recipient.key.len() == 256, "当前仅支持 RSA-2048 数字信封");
        let explicit = param["certPwd"].as_str().filter(|s| !s.is_empty());
        let mut auth =
            Auth::new(self.client.clone(), record.binding.clone(), explicit, true).await?;
        let result=async {
            let block=match auth.hardware(&record.device_id,&recipient.key,true).await {
                Err(error) if auth.without_pin()&&matches!(error.downcast_ref::<HardwareError>(),Some(HardwareError::AuthRequired))=>{auth.require_pin().await?;auth.hardware(&record.device_id,&recipient.key,true).await?},
                other=>other?,
            };
            let plaintext=crypto::decrypt_envelope(&env,recipient,&block,&record.cert.x509)?;let clear=crypto::b64(&plaintext);auth.finish().await?;
            self.client.audit("enveloped_data_decrypted",json!({"contentBytes":plaintext.len(),"certificateFileId":record.file_id}));
            Ok::<_,anyhow::Error>(json!({"clearValue":clear,"clearEncodeType":"base64","clearText":clear,"decryptValue":clear,"decryptValueType":"base64","algo":if env.bits==128{4}else{6},"certObject":record.public()}))
        }.await;
        if result.is_err() {
            auth.fail().await;
        }
        result
    }
}
