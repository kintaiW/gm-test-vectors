use std::path::Path;

use libsmx::sm3::{Sm3Hasher, hmac_sm3};
use crate::parser::{Record, get_field, hex_to_bytes};

/// 验证 SM3 哈希测试向量文件
pub fn verify_sm3(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let msg_hex = get_field(record, "消息")?;
        let expected_hash_hex = get_field(record, "杂凑值")?;

        let msg = hex_to_bytes(msg_hex)?;
        let hash = Sm3Hasher::digest(&msg);
        let actual_hex = hex::encode_upper(&hash);

        if actual_hex.eq_ignore_ascii_case(expected_hash_hex) {
            passed += 1;
        } else {
            eprintln!(
                "  [FAIL] {}: 记录 #{} SM3 哈希不匹配\n    期望: {}\n    实际: {}",
                path.display(), i + 1, expected_hash_hex, actual_hex
            );
        }
    }

    Ok((passed, total))
}

/// 验证 SM3 HMAC 测试向量文件
pub fn verify_sm3_hmac(path: &Path, records: &[Record]) -> Result<(usize, usize), String> {
    let total = records.len();
    let mut passed = 0;

    for (i, record) in records.iter().enumerate() {
        let key_hex = get_field(record, "密钥")?;
        let msg_hex = get_field(record, "消息")?;
        let expected_mac_hex = get_field(record, "MAC值")?;

        let key = hex_to_bytes(key_hex)?;
        let msg = hex_to_bytes(msg_hex)?;
        let mac = hmac_sm3(&key, &msg);
        let actual_hex = hex::encode_upper(&mac);

        if actual_hex.eq_ignore_ascii_case(expected_mac_hex) {
            passed += 1;
        } else {
            eprintln!(
                "  [FAIL] {}: 记录 #{} SM3 HMAC 不匹配\n    期望: {}\n    实际: {}",
                path.display(), i + 1, expected_mac_hex, actual_hex
            );
        }
    }

    Ok((passed, total))
}
