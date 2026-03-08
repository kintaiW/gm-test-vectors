use std::path::Path;

use libsmx::sm2::{self, PrivateKey};
use crate::parser::{Record, get_field, hex_to_bytes, hex_to_array};

/// 公钥从 64 字节（x||y）加上 04 前缀 -> 65 字节
fn pub_key_add_prefix(pk_raw: &[u8]) -> [u8; 65] {
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..].copy_from_slice(pk_raw);
    pk
}

/// 密文加上 C1 的 04 前缀
/// 输入格式: x1||y1 || C3 || C2 (64 + 32 + plaintext_len)
/// 输出格式: 04||x1||y1 || C3 || C2 (65 + 32 + plaintext_len)
fn ciphertext_add_c1_prefix(ct_raw: &[u8]) -> Vec<u8> {
    let mut ct = Vec::with_capacity(1 + ct_raw.len());
    ct.push(0x04);
    ct.extend_from_slice(ct_raw);
    ct
}

/// 验证 SM2 加密/解密测试向量（通过解密验证）
pub fn verify_sm2_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let pri_key_hex = get_field(record, "私钥")?;
        let ct_hex = get_field(record, "密文")?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pri_key_bytes: [u8; 32] = hex_to_array(pri_key_hex)?;
        let pri_key = PrivateKey::from_bytes(&pri_key_bytes)
            .map_err(|e| format!("私钥解析失败: {:?}", e))?;
        let ct_raw = hex_to_bytes(ct_hex)?;
        let expected_pt = hex_to_bytes(expected_pt_hex)?;

        let ct_full = ciphertext_add_c1_prefix(&ct_raw);

        match sm2::decrypt(&pri_key, &ct_full) {
            Ok(decrypted) => {
                if decrypted == expected_pt {
                    passed += 1;
                } else {
                    eprintln!(
                        "  [FAIL] {}: 记录 #{} SM2 解密结果不匹配",
                        path.display(), i + 1
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "  [FAIL] {}: 记录 #{} SM2 解密失败: {:?}",
                    path.display(), i + 1, e
                );
            }
        }
    }

    Ok((passed, total))
}

/// 验证 SM2 签名/验签测试向量（通过验签验证）
pub fn verify_sm2_sign(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let pk_hex = get_field(record, "公钥")?;
        let e_hex = get_field(record, "签名数据e")?;
        let sig_hex = get_field(record, "签名结果")?;

        let pk_raw = hex_to_bytes(pk_hex)?;
        let pub_key = pub_key_add_prefix(&pk_raw);

        let e: [u8; 32] = hex_to_array(e_hex)?;
        let sig: [u8; 64] = hex_to_array(sig_hex)?;

        match sm2::verify(&e, &pub_key, &sig) {
            Ok(()) => {
                passed += 1;
            }
            Err(e_msg) => {
                eprintln!(
                    "  [FAIL] {}: 记录 #{} SM2 验签失败: {}",
                    path.display(), i + 1, e_msg
                );
            }
        }
    }

    Ok((passed, total))
}
