use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::{
    hash::{MessageDigest, hash},
    rand::rand_bytes,
    rsa::Padding,
    symm::{Cipher, decrypt, encrypt},
    x509::X509,
};
use zeroize::Zeroizing;

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub fn decode(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len() <= 2 * 1024 * 1024, "Base64 数据过长");
    let bytes = B64
        .decode(text)
        .map_err(|_| anyhow::anyhow!("Base64 格式无效"))?;
    ensure!(b64(&bytes) == text, "Base64 编码不规范");
    Ok(bytes)
}
pub fn cert_decode(text: &str) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty() && text.len() <= 256 * 1024,
        "加密证书编码无效"
    );
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let encoded = compact
        .strip_prefix("-----BEGINCERTIFICATE-----")
        .and_then(|s| s.strip_suffix("-----ENDCERTIFICATE-----"))
        .unwrap_or(&compact);
    decode(encoded)
}
pub fn digest(bytes: &[u8], sha1: bool) -> Vec<u8> {
    hash(
        if sha1 {
            MessageDigest::sha1()
        } else {
            MessageDigest::sha256()
        },
        bytes,
    )
    .unwrap()
    .to_vec()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = parts.to_vec();
    parts.sort();
    der(0x31, &parts.concat())
}
fn int(n: u8) -> Vec<u8> {
    der(2, &[n])
}
pub fn oid(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text.split('.').map(|v| v.parse().unwrap()).collect();
    let mut bytes = vec![(parts[0] * 40 + parts[1]) as u8];
    for mut n in parts.into_iter().skip(2) {
        let mut part = vec![(n & 127) as u8];
        n >>= 7;
        while n > 0 {
            part.insert(0, 128 | (n & 127) as u8);
            n >>= 7;
        }
        bytes.extend(part);
    }
    der(6, &bytes)
}
fn alg(text: &str, null: bool) -> Vec<u8> {
    if null {
        seq(&[oid(text), der(5, &[])])
    } else {
        seq(&[oid(text)])
    }
}

#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub raw: &'a [u8],
    pub data: &'a [u8],
}
pub fn read(bytes: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    ensure!(bytes.len() >= 2, "DER 数据不完整");
    let mut offset = 2;
    let mut len = usize::from(bytes[1]);
    if len & 128 != 0 {
        let count = len & 127;
        ensure!(
            count > 0 && count <= 6 && bytes.len() >= 2 + count,
            "DER 长度无效"
        );
        ensure!(bytes[2] != 0, "DER 长度不规范");
        len = 0;
        for b in &bytes[2..2 + count] {
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(*b as usize))
                .ok_or_else(|| anyhow::anyhow!("DER 长度无效"))?;
        }
        ensure!(len >= 128, "DER 长度不规范");
        offset += count;
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("DER 长度无效"))?;
    ensure!(end <= bytes.len(), "DER 数据不完整");
    Ok((
        Tlv {
            tag: bytes[0],
            raw: &bytes[..end],
            data: &bytes[offset..end],
        },
        &bytes[end..],
    ))
}
pub fn children(bytes: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut bytes = bytes;
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let (item, rest) = read(bytes)?;
        result.push(item);
        bytes = rest;
    }
    Ok(result)
}
fn root(bytes: &[u8], tag: u8) -> Result<Tlv<'_>> {
    let (value, rest) = read(bytes)?;
    ensure!(value.tag == tag && rest.is_empty(), "DER 结构无效");
    Ok(value)
}
pub fn issuer_serial(bytes: &[u8]) -> Result<Vec<u8>> {
    let outer = root(bytes, 0x30)?;
    let fields = children(outer.data)?;
    let tbs = children(
        fields
            .first()
            .ok_or_else(|| anyhow::anyhow!("证书主体无效"))?
            .data,
    )?;
    let i = usize::from(tbs.first().is_some_and(|v| v.tag == 0xa0));
    ensure!(
        tbs.len() > i + 2 && tbs[i].tag == 2 && tbs[i + 2].tag == 0x30,
        "证书主体无效"
    );
    Ok(seq(&[tbs[i + 2].raw.to_vec(), tbs[i].raw.to_vec()]))
}
pub fn key_usage(bytes: &[u8]) -> Result<Option<u16>> {
    let outer = root(bytes, 0x30)?;
    let fields = children(outer.data)?;
    let tbs = children(
        fields
            .first()
            .ok_or_else(|| anyhow::anyhow!("证书主体无效"))?
            .data,
    )?;
    for ext in tbs.iter().filter(|v| v.tag == 0xa3) {
        let sequence = root(ext.data, 0x30)?;
        for entry in children(sequence.data)? {
            let fields = children(entry.data)?;
            if fields.first().is_none_or(|v| v.raw != oid("2.5.29.15")) {
                continue;
            }
            let value = fields
                .last()
                .ok_or_else(|| anyhow::anyhow!("证书 KeyUsage 无效"))?;
            ensure!(value.tag == 4, "证书 KeyUsage 无效");
            let bits = root(value.data, 3)?;
            ensure!(bits.data.len() >= 2, "证书 KeyUsage 无效");
            let mut mask = 0;
            for bit in 0..8 {
                if bits.data[1] & (0x80 >> bit) != 0 {
                    mask |= 1 << bit;
                }
            }
            if bits.data.len() > 2 && bits.data[2] & 0x80 != 0 {
                mask |= 0x100;
            }
            return Ok(Some(mask));
        }
    }
    Ok(None)
}
pub fn ski(cert: &X509) -> Result<Vec<u8>> {
    let spki = cert.public_key()?.public_key_to_der()?;
    let outer = root(&spki, 0x30)?;
    let fields = children(outer.data)?;
    ensure!(
        fields.len() == 2 && fields[1].tag == 3 && fields[1].data.first() == Some(&0),
        "证书公钥格式不受支持"
    );
    Ok(digest(&fields[1].data[1..], true))
}
pub fn digest_info(content: &[u8], sha1: bool) -> Vec<u8> {
    let prefix = if sha1 {
        "3021300906052b0e03021a05000414"
    } else {
        "3031300d060960864801650304020105000420"
    };
    let mut out: Vec<u8> = (0..prefix.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&prefix[i..i + 2], 16).unwrap())
        .collect();
    out.extend(digest(content, sha1));
    out
}
/// Builds a detached SignedData (PKCS#7) for one signer.
///
/// `certificate` always lands in the `[0]` certificates field, regardless of the
/// request's `includeCertOption`; see the note at the call site in `rpc.rs`.
pub fn signed(
    certificate: &[u8],
    signature: &[u8],
    sha1: bool,
    native_default: bool,
) -> Result<Vec<u8>> {
    let digest = alg(
        if sha1 {
            "1.3.14.3.2.26"
        } else {
            "2.16.840.1.101.3.4.2.1"
        },
        false,
    );
    let sig_alg = if native_default {
        "1.2.840.113549.1.1.1"
    } else if sha1 {
        "1.2.840.113549.1.1.5"
    } else {
        "1.2.840.113549.1.1.11"
    };
    let signer = seq(&[
        int(1),
        issuer_serial(certificate)?,
        digest.clone(),
        alg(sig_alg, true),
        der(4, signature),
    ]);
    let data = seq(&[
        int(1),
        set(&[digest]),
        seq(&[oid("1.2.840.113549.1.7.1")]),
        der(0xa0, certificate),
        set(&[signer]),
    ]);
    Ok(seq(&[oid("1.2.840.113549.1.7.2"), der(0xa0, &data)]))
}
pub fn envelop(cert: &X509, plaintext: &[u8], bits: usize) -> Result<Vec<u8>> {
    ensure!(bits == 128 || bits == 256, "AES 密钥长度无效");
    let mut key = Zeroizing::new(vec![0; bits / 8]);
    let mut iv = vec![0; 16];
    rand_bytes(&mut key)?;
    rand_bytes(&mut iv)?;
    let encrypted = encrypt(
        if bits == 128 {
            Cipher::aes_128_cbc()
        } else {
            Cipher::aes_256_cbc()
        },
        &key,
        Some(&iv),
        plaintext,
    )?;
    let rsa = cert
        .public_key()?
        .rsa()
        .map_err(|_| anyhow::anyhow!("EnvelopedData 当前仅支持 RSA 加密证书"))?;
    let mut wrapped = vec![0; rsa.size() as usize];
    let n = rsa.public_encrypt(&key, &mut wrapped, Padding::PKCS1)?;
    wrapped.truncate(n);
    let recipient = seq(&[
        int(2),
        der(0x80, &ski(cert)?),
        alg("1.2.840.113549.1.1.1", true),
        der(4, &wrapped),
    ]);
    let content = seq(&[
        oid("1.2.840.113549.1.7.1"),
        seq(&[
            oid(if bits == 128 {
                "2.16.840.1.101.3.4.1.2"
            } else {
                "2.16.840.1.101.3.4.1.42"
            }),
            der(4, &iv),
        ]),
        der(0x80, &encrypted),
    ]);
    Ok(seq(&[
        oid("1.2.840.113549.1.7.3"),
        der(0xa0, &seq(&[int(2), set(&[recipient]), content])),
    ]))
}
pub struct Recipient {
    pub ski: Option<Vec<u8>>,
    pub issuer_serial: Option<Vec<u8>>,
    pub key: Vec<u8>,
}
pub struct Envelope {
    pub recipients: Vec<Recipient>,
    pub bits: usize,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
pub fn parse_envelope(encoded: &str) -> Result<Envelope> {
    let bytes = decode(encoded)?;
    let ci = children(root(&bytes, 0x30)?.data)?;
    ensure!(
        ci.len() == 2 && ci[0].raw == oid("1.2.840.113549.1.7.3") && ci[1].tag == 0xa0,
        "不支持的数字信封结构"
    );
    let env = children(root(ci[1].data, 0x30)?.data)?;
    ensure!(
        env.len() == 3 && env[0].tag == 2 && env[1].tag == 0x31 && env[2].tag == 0x30,
        "不支持的数字信封结构"
    );
    let mut recipients = Vec::new();
    for entry in children(env[1].data)? {
        ensure!(entry.tag == 0x30, "不支持的接收方结构");
        let fields = children(entry.data)?;
        ensure!(
            fields.len() == 4 && fields[0].tag == 2 && fields[2].tag == 0x30 && fields[3].tag == 4,
            "不支持的接收方结构"
        );
        let algorithm = children(fields[2].data)?;
        ensure!(
            algorithm
                .first()
                .is_some_and(|a| a.raw == oid("1.2.840.113549.1.1.1")),
            "不支持的密钥算法"
        );
        ensure!(
            fields[1].tag == 0x80 || fields[1].tag == 0x30,
            "不支持的接收方标识"
        );
        recipients.push(Recipient {
            ski: (fields[1].tag == 0x80).then(|| fields[1].data.to_vec()),
            issuer_serial: (fields[1].tag == 0x30).then(|| fields[1].raw.to_vec()),
            key: fields[3].data.to_vec(),
        });
    }
    let content = children(env[2].data)?;
    ensure!(
        content.len() == 3
            && content[0].raw == oid("1.2.840.113549.1.7.1")
            && content[1].tag == 0x30
            && content[2].tag == 0x80,
        "不支持的加密内容结构"
    );
    let algorithm = children(content[1].data)?;
    ensure!(
        algorithm.len() == 2 && algorithm[1].tag == 4 && algorithm[1].data.len() == 16,
        "数字信封 IV 无效"
    );
    let bits = if algorithm[0].raw == oid("2.16.840.1.101.3.4.1.2") {
        128
    } else if algorithm[0].raw == oid("2.16.840.1.101.3.4.1.42") {
        256
    } else {
        bail!("不支持的数字信封算法");
    };
    ensure!(
        !content[2].data.is_empty() && content[2].data.len().is_multiple_of(16),
        "数字信封密文长度无效"
    );
    Ok(Envelope {
        recipients,
        bits,
        iv: algorithm[1].data.to_vec(),
        ciphertext: content[2].data.to_vec(),
    })
}
pub fn decrypt_envelope(
    env: &Envelope,
    recipient: &Recipient,
    block: &[u8],
    cert: &X509,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(block.len() == 256, "USBKey 解密结果无效");
    let rsa = cert.public_key()?.rsa()?;
    let mut check = vec![0; rsa.size() as usize];
    let n = rsa.public_encrypt(block, &mut check, Padding::NONE)?;
    ensure!(check[..n] == recipient.key, "USBKey 解密结果未通过公钥自检");
    let sep = block[2..]
        .iter()
        .position(|b| *b == 0)
        .map(|i| i + 2)
        .unwrap_or(0);
    ensure!(
        block[0] == 0 && block[1] == 2 && sep >= 10 && block.len() - sep - 1 == env.bits / 8,
        "数字信封 RSA 密钥填充无效"
    );
    let key = Zeroizing::new(block[sep + 1..].to_vec());
    decrypt(
        if env.bits == 128 {
            Cipher::aes_128_cbc()
        } else {
            Cipher::aes_256_cbc()
        },
        &key,
        Some(&env.iv),
        &env.ciphertext,
    )
    .map(Zeroizing::new)
    .map_err(|_| anyhow::anyhow!("数字信封内容解密失败"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_der_and_base64_fail_without_panicking() {
        for bytes in [
            vec![],
            vec![0x30],
            vec![0x30, 0x80],
            vec![0x30, 0x81, 0x01, 0],
            vec![0x30, 0x88, 255, 255],
            vec![0x30, 0x00],
        ] {
            assert!(parse_envelope(&b64(&bytes)).is_err());
        }
        assert!(decode("AB==").is_err());
        assert!(decode("%%%").is_err());
        for len in [0, 1, 127, 128, 256, 65536] {
            let encoded = der(4, &vec![1; len]);
            let (value, rest) = read(&encoded).unwrap();
            assert!(rest.is_empty());
            assert_eq!(value.data.len(), len);
        }
    }
}
