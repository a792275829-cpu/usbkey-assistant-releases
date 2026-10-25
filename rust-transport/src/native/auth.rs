use super::{Client, crypto};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum HardwareError {
    PinRejected { result: i64, retries: i64 },
    AuthRequired,
}
impl std::fmt::Display for HardwareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PinRejected { .. } => "证书密码验证失败",
                Self::AuthRequired => "需要 USBKey 认证",
            }
        )
    }
}
impl std::error::Error for HardwareError {}

pub struct Auth {
    client: Client,
    binding: String,
    token: u64,
    pin: Option<Zeroizing<String>>,
    persisted: bool,
    marked: bool,
}
fn valid(pin: &str) -> Result<()> {
    ensure!(
        !pin.is_empty() && pin.len() <= 64 && !pin.contains(['\r', '\n', '\0']),
        "证书密码格式无效"
    );
    Ok(())
}
impl Auth {
    pub async fn new(
        client: Client,
        binding: String,
        explicit: Option<&str>,
        allow_without: bool,
    ) -> Result<Self> {
        if let Some(pin) = explicit {
            valid(pin)?;
        }
        let mut request = json!({"operation":"begin","binding":binding});
        if let Some(pin) = explicit {
            request["pin"] = json!(pin);
        }
        let mut initial = client.state(request).await?;
        let pin = match initial["pin"].take() {
            Value::String(s) => Some(Zeroizing::new(s)),
            _ => None,
        };
        let mut auth = Self {
            client,
            binding,
            token: initial["token"].as_u64().unwrap(),
            pin,
            persisted: initial["persisted"] == true,
            marked: false,
        };
        let result=async {
            if auth.pin.is_none() {
                match auth.client.store("read",&auth.binding,None).await {
                    Ok(mut reply)=>if let Value::String(pin)=reply["pin"].take(){let pin=Zeroizing::new(pin);if valid(&pin).is_ok(){auth.client.state(json!({"operation":"provide","token":auth.token,"pin":pin.as_str(),"persisted":true})).await?;auth.pin=Some(pin);auth.persisted=true;}},
                    Err(_)=>auth.client.audit("pin_store_unavailable",json!({"operation":"read"})),
                }
                auth.check().await?;
            }
            if auth.pin.is_some()||!allow_without {auth.require_pin().await?;}
            Ok::<_,anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            auth.fail().await;
            return Err(error);
        }
        Ok(auth)
    }
    pub fn without_pin(&self) -> bool {
        self.pin.is_none()
    }
    async fn check(&self) -> Result<()> {
        self.client
            .state(json!({"operation":"check","token":self.token}))
            .await?;
        Ok(())
    }
    pub async fn require_pin(&mut self) -> Result<()> {
        if self.pin.is_none() {
            let mut result = self
                .client
                .helper("prompt", &[], "", None)
                .await
                .map_err(|_| anyhow::anyhow!("用户取消了 USBKey 证书密码输入"))?;
            ensure!(result["code"] == 0, "用户取消了 USBKey 证书密码输入");
            let output = match result["stdout"].take() {
                Value::String(s) => Zeroizing::new(s),
                _ => bail!("证书密码格式无效"),
            };
            let pin = Zeroizing::new(output.trim_end_matches(['\r', '\n']).to_owned());
            valid(&pin)?;
            self.client.state(json!({"operation":"provide","token":self.token,"pin":pin.as_str(),"persisted":false})).await?;
            self.pin = Some(pin);
        }
        if !self.marked {
            self.client
                .state(json!({"operation":"attempt","token":self.token}))
                .await?;
            self.marked = true;
        }
        Ok(())
    }
    pub async fn hardware(
        &self,
        device: &str,
        data: &[u8],
        decrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let operation = if !decrypt {
            "--sign-digest-info"
        } else if self.pin.is_none() {
            "--decrypt-rsa-block-no-pin"
        } else {
            "--decrypt-rsa-block"
        };
        let input = Zeroizing::new(if let Some(pin) = &self.pin {
            format!("{}\n{}\n", pin.as_str(), crypto::b64(data))
        } else {
            format!("{}\n", crypto::b64(data))
        });
        let result = self
            .client
            .helper(
                "signer",
                &[operation.into(), "--device-id".into(), device.into()],
                &input,
                Some(self.token),
            )
            .await?;
        let value: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
            .map_err(|_| anyhow::anyhow!("FT3000GM 签名助手返回无效结果"))?;
        let output = if decrypt {
            "rsa_block_base64"
        } else {
            "signature_base64"
        };
        if result["code"] != 0
            || value[if decrypt { "decrypted" } else { "signed" }] != true
            || !value[output].is_string()
        {
            self.client.audit("signer_failure",json!({"exitCode":result["code"],"pinStatusWord":value["verify_sw"],"retries":value["retries"],"signatureStatusWord":value["signature_sw"]}));
            if value["device_found"] == false {
                bail!("未发现所选 USBKey");
            }
            if value["df_authenticated"] == false {
                bail!("USBKey 应用目录认证失败");
            }
            if value["pin_verified"] == false {
                let sw = value["verify_sw"].as_str().unwrap_or("").to_uppercase();
                let retries = value["retries"].as_i64().filter(|v| *v >= 0).unwrap_or(-1);
                if sw == "6983"
                    || (sw.len() == 4
                        && sw.starts_with("63C")
                        && sw.as_bytes()[3].is_ascii_hexdigit())
                {
                    return Err(HardwareError::PinRejected {
                        result: if sw == "6983" { -81 } else { -5 },
                        retries,
                    }
                    .into());
                }
                bail!("证书密码验证失败");
            }
            if operation == "--decrypt-rsa-block-no-pin" && value["signature_sw"] == "6982" {
                return Err(HardwareError::AuthRequired.into());
            }
            bail!(
                "{}",
                if decrypt {
                    "USBKey 解密失败"
                } else {
                    "USBKey 签名失败"
                }
            );
        }
        Ok(Zeroizing::new(crypto::decode(
            value[output].as_str().unwrap(),
        )?))
    }
    pub async fn finish(&mut self) -> Result<()> {
        self.check().await?;
        if let Some(pin) = &self.pin {
            if !self.persisted {
                match self.client.store("write", &self.binding, Some(pin)).await {
                    Ok(_) => {
                        self.persisted = true;
                        self.client.audit("pin_store_saved", json!({}));
                    }
                    Err(_) => self
                        .client
                        .audit("pin_store_unavailable", json!({"operation":"write"})),
                }
                self.check().await?;
            }
            self.client
                .state(json!({"operation":"commit","token":self.token,"persisted":self.persisted}))
                .await?;
        } else {
            self.client
                .state(json!({"operation":"finish_without_pin","token":self.token}))
                .await?;
        }
        Ok(())
    }
    pub async fn fail(&self) {
        if let Ok(result) = self
            .client
            .state(json!({"operation":"fail","token":self.token}))
            .await
            && result["removeSaved"] == true
            && self
                .client
                .store("remove", &self.binding, None)
                .await
                .is_err()
        {
            self.client
                .audit("pin_store_unavailable", json!({"operation":"remove"}));
        }
    }
}
