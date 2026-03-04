use std::path::Path;

use crypto_bigint::{U256, Zero};
use gm_sdk::{
    sm2_generate_keypair, sm2_encrypt, sm2_decrypt,
    sm2_sign_with_k, sm2_sign_verify,
};
use rand::RngCore;

use crate::format::write_records_to_file;
use crate::utils::*;

/// SM2 曲线阶 n
const SM2_ORDER: U256 = U256::from_be_hex(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
);

/// SM2 加密测试向量的明文长度序列
const SM2_ENC_PLAINTEXT_LENGTHS: &[usize] = &[
    0x10, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
];

/// 用预计算的 e 值进行 SM2 签名（内部循环生成随机 k）
fn sm2_sign_with_e(e: &[u8; 32], pri_key: &[u8; 32]) -> [u8; 64] {
    loop {
        let mut k_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);

        // k 必须在 [1, n-1] 范围内
        if k.is_zero().into() || k >= SM2_ORDER {
            continue;
        }

        match sm2_sign_with_k(e, pri_key, &k) {
            Ok(sig) => return sig,
            Err(_) => continue,
        }
    }
}

/// 公钥从 65 字节（04||x||y）格式去掉 04 前缀 -> 64 字节
fn pub_key_strip_prefix(pk: &[u8; 65]) -> Vec<u8> {
    pk[1..].to_vec()
}

/// SM2 密文去掉 C1 的 04 前缀
/// 输入格式: 04||x1||y1 || C3 || C2 (65 + 32 + plaintext_len)
/// 输出格式: x1||y1 || C3 || C2 (64 + 32 + plaintext_len)
fn ciphertext_strip_c1_prefix(ct: &[u8]) -> Vec<u8> {
    // 跳过第一个字节 (0x04)
    ct[1..].to_vec()
}

/// 生成 SM2 加密/解密测试向量
pub fn generate_sm2_encrypt(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let (pri_key, pub_key) = sm2_generate_keypair();
    let mut records = Vec::new();

    for i in 0..count {
        let pt_len = SM2_ENC_PLAINTEXT_LENGTHS[i % SM2_ENC_PLAINTEXT_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        // 加密
        let ciphertext_full = sm2_encrypt(&pub_key, &plaintext);

        // 自验证：解密并比较
        let decrypted = sm2_decrypt(&pri_key, &ciphertext_full)
            .expect("SM2 解密自验证失败");
        assert_eq!(plaintext, decrypted, "SM2 加密/解密自验证不一致");

        // 转换格式：去掉 C1 的 04 前缀
        let ct_raw = ciphertext_strip_c1_prefix(&ciphertext_full);

        records.push(vec![
            ("公钥", to_hex_upper(&pub_key_strip_prefix(&pub_key))),
            ("私钥", to_hex_upper(&pri_key)),
            ("密文长度", len_hex(ct_raw.len())),
            ("密文", to_hex_upper(&ct_raw)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    // 输出"解密格式"文件（用于测试解密功能）
    let path1 = output_dir.join(format!("SM2_加密_{}（解密格式）.txt", count));
    write_records_to_file(&path1, &records)?;
    println!("  已生成: {}", path1.display());

    // 输出"解密"文件（与解密格式相同数据）
    let path2 = output_dir.join(format!("SM2_解密_{}.txt", count));
    write_records_to_file(&path2, &records)?;
    println!("  已生成: {}", path2.display());

    Ok(())
}

/// 生成 SM2 签名/验签测试向量（预处理后格式，使用 e 值）
pub fn generate_sm2_sign(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let (pri_key, pub_key) = sm2_generate_keypair();
    let mut sign_records = Vec::new(); // 包含私钥（签名格式）
    let mut verify_records = Vec::new(); // 不含私钥（验签格式）

    for _ in 0..count {
        // 生成随机的预处理 e 值（模拟 SM3(Z||M) 的输出）
        let e: [u8; 32] = random_bytes_array();

        // 用 e 值签名
        let sig = sm2_sign_with_e(&e, &pri_key);

        // 自验证：验签
        let pub_key_65 = pub_key;
        sm2_sign_verify(&e, &pub_key_65, &sig)
            .expect("SM2 签名自验证失败");

        let pk_hex = to_hex_upper(&pub_key_strip_prefix(&pub_key));

        // 签名格式（包含私钥，用于测试签名功能）
        sign_records.push(vec![
            ("公钥", pk_hex.clone()),
            ("私钥", to_hex_upper(&pri_key)),
            ("签名数据e", to_hex_upper(&e)),
            ("签名结果", to_hex_upper(&sig)),
        ]);

        // 验签格式（不含私钥，用于测试验签功能）
        verify_records.push(vec![
            ("公钥", pk_hex),
            ("签名数据e", to_hex_upper(&e)),
            ("签名结果", to_hex_upper(&sig)),
        ]);
    }

    let path1 = output_dir.join(format!("SM2验签_预处理后_{}.txt", count));
    write_records_to_file(&path1, &sign_records)?;
    println!("  已生成: {}", path1.display());

    let path2 = output_dir.join(format!("SM2签名_预处理后_{}（验签格式）.txt", count));
    write_records_to_file(&path2, &verify_records)?;
    println!("  已生成: {}", path2.display());

    Ok(())
}
