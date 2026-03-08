use std::path::Path;

use libsmx::sm3::{Sm3Hasher, hmac_sm3};
use crate::format::write_records_to_file;
use crate::utils::*;

/// SM3 哈希测试向量的数据长度序列（16 字节递增）
const SM3_DATA_LENGTHS: &[usize] = &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0];

/// 生成 SM3 哈希测试向量
pub fn generate_sm3(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let mut records = Vec::new();

    for i in 0..count {
        let msg_len = SM3_DATA_LENGTHS[i % SM3_DATA_LENGTHS.len()];
        let msg = random_bytes(msg_len);

        let hash = Sm3Hasher::digest(&msg);

        let hash_verify = Sm3Hasher::digest(&msg);
        assert_eq!(hash, hash_verify, "SM3 自验证失败");

        records.push(vec![
            ("消息长度", len_hex(msg_len)),
            ("消息", to_hex_upper(&msg)),
            ("杂凑值", to_hex_upper(&hash)),
        ]);
    }

    let path = output_dir.join(format!("SM3_{}.txt", count));
    write_records_to_file(&path, &records)?;
    println!("  已生成: {}", path.display());
    Ok(())
}

/// 生成 SM3 HMAC 测试向量
pub fn generate_sm3_hmac(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let mut records = Vec::new();

    for i in 0..count {
        let msg_len = SM3_DATA_LENGTHS[i % SM3_DATA_LENGTHS.len()];
        let key = random_bytes(32);
        let msg = random_bytes(msg_len);

        let mac = hmac_sm3(&key, &msg);

        let mac_verify = hmac_sm3(&key, &msg);
        assert_eq!(mac, mac_verify, "SM3 HMAC 自验证失败");

        records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("消息", to_hex_upper(&msg)),
            ("MAC值", to_hex_upper(&mac)),
        ]);
    }

    let path = output_dir.join(format!("SM3_HMAC_{}.txt", count));
    write_records_to_file(&path, &records)?;
    println!("  已生成: {}", path.display());
    Ok(())
}
