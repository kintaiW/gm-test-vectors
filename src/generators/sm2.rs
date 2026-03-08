use std::path::Path;

use crypto_bigint::{U256, Zero};
use libsmx::sm2::{self, PrivateKey};
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
fn sm2_sign_with_e(e: &[u8; 32], pri_key: &PrivateKey) -> [u8; 64] {
    loop {
        let mut k_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);

        if k.is_zero().into() || k >= SM2_ORDER {
            continue;
        }

        match sm2::sign_with_k(e, pri_key, &k) {
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
    ct[1..].to_vec()
}

/// 生成 SM2 加密/解密测试向量
pub fn generate_sm2_encrypt(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let mut rng = rand::rngs::OsRng;
    let (pri_key, pub_key) = sm2::generate_keypair(&mut rng);
    let mut records = Vec::new();

    for i in 0..count {
        let pt_len = SM2_ENC_PLAINTEXT_LENGTHS[i % SM2_ENC_PLAINTEXT_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let ciphertext_full = sm2::encrypt(&pub_key, &plaintext, &mut rng)
            .expect("SM2 加密失败");

        let decrypted = sm2::decrypt(&pri_key, &ciphertext_full)
            .expect("SM2 解密自验证失败");
        assert_eq!(plaintext, decrypted, "SM2 加密/解密自验证不一致");

        let ct_raw = ciphertext_strip_c1_prefix(&ciphertext_full);

        records.push(vec![
            ("公钥", to_hex_upper(&pub_key_strip_prefix(&pub_key))),
            ("私钥", to_hex_upper(pri_key.as_bytes())),
            ("密文长度", len_hex(ct_raw.len())),
            ("密文", to_hex_upper(&ct_raw)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path1 = output_dir.join(format!("SM2_加密_{}（解密格式）.txt", count));
    write_records_to_file(&path1, &records)?;
    println!("  已生成: {}", path1.display());

    let path2 = output_dir.join(format!("SM2_解密_{}.txt", count));
    write_records_to_file(&path2, &records)?;
    println!("  已生成: {}", path2.display());

    Ok(())
}

/// 生成 SM2 签名/验签测试向量（预处理后格式，使用 e 值）
pub fn generate_sm2_sign(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let mut rng = rand::rngs::OsRng;
    let (pri_key, pub_key) = sm2::generate_keypair(&mut rng);
    let mut sign_records = Vec::new();
    let mut verify_records = Vec::new();

    for _ in 0..count {
        let e: [u8; 32] = random_bytes_array();

        let sig = sm2_sign_with_e(&e, &pri_key);

        let pub_key_65 = pub_key;
        sm2::verify(&e, &pub_key_65, &sig)
            .expect("SM2 签名自验证失败");

        let pk_hex = to_hex_upper(&pub_key_strip_prefix(&pub_key));

        sign_records.push(vec![
            ("公钥", pk_hex.clone()),
            ("私钥", to_hex_upper(pri_key.as_bytes())),
            ("签名数据e", to_hex_upper(&e)),
            ("签名结果", to_hex_upper(&sig)),
        ]);

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
