use std::path::Path;

use libsmx::sm4::{
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
    sm4_encrypt_cfb, sm4_decrypt_cfb,
    sm4_crypt_ofb,
    sm4_crypt_ctr,
    sm4_encrypt_gcm, sm4_decrypt_gcm,
    sm4_encrypt_xts, sm4_decrypt_xts,
};

use crate::parser::{Record, get_field, hex_to_bytes, hex_to_array};

/// 通用的比较辅助
fn check_hex_eq(actual: &[u8], expected_hex: &str) -> bool {
    let actual_hex = hex::encode(actual);
    actual_hex.eq_ignore_ascii_case(expected_hex)
}

// ─── ECB ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_ecb_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let ct = sm4_encrypt_ecb(&key, &pt);
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-ECB 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_ecb_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pt = sm4_decrypt_ecb(&key, &ct);
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-ECB 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── CBC ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_cbc_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let ct = sm4_encrypt_cbc(&key, &iv, &pt);
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CBC 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_cbc_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pt = sm4_decrypt_cbc(&key, &iv, &ct);
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CBC 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── CFB ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_cfb_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let ct = sm4_encrypt_cfb(&key, &iv, &pt);
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CFB 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_cfb_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pt = sm4_decrypt_cfb(&key, &iv, &ct);
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CFB 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── OFB ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_ofb_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let ct = sm4_crypt_ofb(&key, &iv, &pt);
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-OFB 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_ofb_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pt = sm4_crypt_ofb(&key, &iv, &ct);
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-OFB 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── CTR ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_ctr_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let counter: [u8; 16] = hex_to_array(get_field(record, "counter")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let ct = sm4_crypt_ctr(&key, &counter, &pt);
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CTR 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_ctr_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let counter: [u8; 16] = hex_to_array(get_field(record, "counter")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let pt = sm4_crypt_ctr(&key, &counter, &ct);
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CTR 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── GCM ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_gcm_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 12] = hex_to_array(get_field(record, "IV")?)?;
        let aad = hex_to_bytes(get_field(record, "aad")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;
        let expected_tag_hex = get_field(record, "tag")?;

        let (ct, tag) = sm4_encrypt_gcm(&key, &iv, &aad, &pt);
        if check_hex_eq(&ct, expected_ct_hex) && check_hex_eq(&tag, expected_tag_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-GCM 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_gcm_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 12] = hex_to_array(get_field(record, "IV")?)?;
        let aad = hex_to_bytes(get_field(record, "aad")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;
        let tag: [u8; 16] = hex_to_array(get_field(record, "tag")?)?;

        match sm4_decrypt_gcm(&key, &iv, &aad, &ct, &tag) {
            Ok(pt) => {
                if check_hex_eq(&pt, expected_pt_hex) {
                    passed += 1;
                } else {
                    eprintln!("  [FAIL] {}: 记录 #{} SM4-GCM 解密结果不匹配", path.display(), i + 1);
                }
            }
            Err(e) => {
                eprintln!("  [FAIL] {}: 记录 #{} SM4-GCM 解密失败: {:?}", path.display(), i + 1, e);
            }
        }
    }
    Ok((passed, total))
}

// ─── XTS ────────────────────────────────────────────────────────────────────

pub fn verify_sm4_xts_encrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key_full = hex_to_bytes(get_field(record, "密钥")?)?;
        let tweak: [u8; 16] = hex_to_array(get_field(record, "tweak")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_ct_hex = get_field(record, "密文")?;

        let key1: [u8; 16] = key_full[..16].try_into()
            .map_err(|_| "XTS 密钥长度不足".to_string())?;
        let key2: [u8; 16] = key_full[16..32].try_into()
            .map_err(|_| "XTS 密钥长度不足".to_string())?;

        let ct = sm4_encrypt_xts(&key1, &key2, &tweak, &pt)
            .map_err(|e| format!("SM4-XTS 加密失败: {:?}", e))?;
        if check_hex_eq(&ct, expected_ct_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-XTS 加密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

pub fn verify_sm4_xts_decrypt(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key_full = hex_to_bytes(get_field(record, "密钥")?)?;
        let tweak: [u8; 16] = hex_to_array(get_field(record, "tweak")?)?;
        let ct = hex_to_bytes(get_field(record, "密文")?)?;
        let expected_pt_hex = get_field(record, "明文")?;

        let key1: [u8; 16] = key_full[..16].try_into()
            .map_err(|_| "XTS 密钥长度不足".to_string())?;
        let key2: [u8; 16] = key_full[16..32].try_into()
            .map_err(|_| "XTS 密钥长度不足".to_string())?;

        let pt = sm4_decrypt_xts(&key1, &key2, &tweak, &ct)
            .map_err(|e| format!("SM4-XTS 解密失败: {:?}", e))?;
        if check_hex_eq(&pt, expected_pt_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-XTS 解密不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}

// ─── CBC-MAC ────────────────────────────────────────────────────────────────

/// CBC-MAC：使用 SM4-CBC 加密，取最后一个分组作为 MAC
fn sm4_cbc_mac(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let ciphertext = sm4_encrypt_cbc(key, iv, data);

    let mut mac = [0u8; 16];
    mac.copy_from_slice(&ciphertext[data.len() - 16..]);
    mac
}

pub fn verify_sm4_cbcmac(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key: [u8; 16] = hex_to_array(get_field(record, "密钥")?)?;
        let iv: [u8; 16] = hex_to_array(get_field(record, "IV")?)?;
        let pt = hex_to_bytes(get_field(record, "明文")?)?;
        let expected_mac_hex = get_field(record, "MAC值")?;

        let mac = sm4_cbc_mac(&key, &iv, &pt);
        if check_hex_eq(&mac, expected_mac_hex) {
            passed += 1;
        } else {
            eprintln!("  [FAIL] {}: 记录 #{} SM4-CBCMAC 不匹配", path.display(), i + 1);
        }
    }
    Ok((passed, total))
}
