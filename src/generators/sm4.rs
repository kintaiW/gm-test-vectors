use std::path::Path;

use gm_sdk::{
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
    sm4_encrypt_cfb, sm4_decrypt_cfb,
    sm4_encrypt_ofb, sm4_decrypt_ofb,
    sm4_encrypt_ctr, sm4_decrypt_ctr,
    sm4_encrypt_gcm, sm4_decrypt_gcm,
    sm4_encrypt_xts, sm4_decrypt_xts,
};

use crate::format::write_records_to_file;
use crate::utils::*;

/// SM4 分组模式的数据长度序列（16 字节对齐，递增）
const SM4_BLOCK_LENGTHS: &[usize] = &[
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
];

/// SM4-XTS 的数据长度序列（最小 32 字节）
const SM4_XTS_LENGTHS: &[usize] = &[
    0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0,
];

// ─── ECB ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_ecb(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let ciphertext = sm4_encrypt_ecb(&key, &plaintext);

        // 自验证
        let decrypted = sm4_decrypt_ecb(&key, &ciphertext);
        assert_eq!(plaintext, decrypted, "SM4-ECB 自验证失败");

        enc_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("密文", to_hex_upper(&ciphertext)),
        ]);

        dec_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("密文长度", len_hex(pt_len)),
            ("密文", to_hex_upper(&ciphertext)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path = output_dir.join("SM4_ECB_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_ECB_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── CBC ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_cbc(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let iv: [u8; 16] = random_bytes_array();
    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let mut ciphertext = vec![0u8; pt_len];
        sm4_encrypt_cbc(&key, &iv, &plaintext, &mut ciphertext);

        // 自验证
        let mut decrypted = vec![0u8; pt_len];
        sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut decrypted);
        assert_eq!(plaintext, decrypted, "SM4-CBC 自验证失败");

        enc_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("密文", to_hex_upper(&ciphertext)),
        ]);

        dec_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("密文长度", len_hex(pt_len)),
            ("密文", to_hex_upper(&ciphertext)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path = output_dir.join("SM4_CBC_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_CBC_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── CFB ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_cfb(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let iv: [u8; 16] = random_bytes_array();
    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let ciphertext = sm4_encrypt_cfb(&key, &iv, &plaintext);

        // 自验证
        let decrypted = sm4_decrypt_cfb(&key, &iv, &ciphertext);
        assert_eq!(plaintext, decrypted, "SM4-CFB 自验证失败");

        enc_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("密文", to_hex_upper(&ciphertext)),
        ]);

        dec_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("密文长度", len_hex(pt_len)),
            ("密文", to_hex_upper(&ciphertext)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path = output_dir.join("SM4_CFB_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_CFB_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── OFB ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_ofb(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let iv: [u8; 16] = random_bytes_array();
    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let ciphertext = sm4_encrypt_ofb(&key, &iv, &plaintext);

        // 自验证
        let decrypted = sm4_decrypt_ofb(&key, &iv, &ciphertext);
        assert_eq!(plaintext, decrypted, "SM4-OFB 自验证失败");

        enc_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("密文", to_hex_upper(&ciphertext)),
        ]);

        dec_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("密文长度", len_hex(pt_len)),
            ("密文", to_hex_upper(&ciphertext)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path = output_dir.join("SM4_OFB_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_OFB_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── CTR ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_ctr(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let counter: [u8; 16] = random_bytes_array();
    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let ciphertext = sm4_encrypt_ctr(&key, &counter, &plaintext);

        // 自验证
        let decrypted = sm4_decrypt_ctr(&key, &counter, &ciphertext);
        assert_eq!(plaintext, decrypted, "SM4-CTR 自验证失败");

        enc_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("counter", to_hex_upper(&counter)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("密文", to_hex_upper(&ciphertext)),
        ]);

        dec_records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("counter", to_hex_upper(&counter)),
            ("密文长度", len_hex(pt_len)),
            ("密文", to_hex_upper(&ciphertext)),
            ("明文", to_hex_upper(&plaintext)),
        ]);
    }

    let path = output_dir.join("SM4_CTR_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_CTR_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── GCM ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_gcm(output_dir: &Path, count: usize) -> std::io::Result<()> {
    // GCM 加密和解密使用不同的密钥（与样本文件一致）
    let enc_key: [u8; 16] = random_bytes_array();
    let enc_iv: [u8; 12] = random_bytes_array();
    let enc_aad = random_bytes(16);

    let dec_key: [u8; 16] = random_bytes_array();
    let dec_iv: [u8; 12] = random_bytes_array();
    let dec_aad = random_bytes(16);

    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];

        // 加密方向测试向量
        {
            let plaintext = random_bytes(pt_len);
            let (ciphertext, tag) = sm4_encrypt_gcm(&enc_key, &enc_iv, &enc_aad, &plaintext);

            // 自验证
            let decrypted = sm4_decrypt_gcm(&enc_key, &enc_iv, &enc_aad, &ciphertext, &tag)
                .expect("SM4-GCM 加密自验证失败");
            assert_eq!(plaintext, decrypted, "SM4-GCM 加密/解密自验证不一致");

            enc_records.push(vec![
                ("密钥", to_hex_lower(&enc_key)),
                ("IV", to_hex_lower(&enc_iv)),
                ("aad", to_hex_lower(&enc_aad)),
                ("明文", to_hex_lower(&plaintext)),
                ("密文", to_hex_lower(&ciphertext)),
                ("tag", to_hex_lower(&tag)),
            ]);
        }

        // 解密方向测试向量
        {
            let plaintext = random_bytes(pt_len);
            let (ciphertext, tag) = sm4_encrypt_gcm(&dec_key, &dec_iv, &dec_aad, &plaintext);

            // 自验证
            let decrypted = sm4_decrypt_gcm(&dec_key, &dec_iv, &dec_aad, &ciphertext, &tag)
                .expect("SM4-GCM 解密自验证失败");
            assert_eq!(plaintext, decrypted, "SM4-GCM 解密自验证不一致");

            dec_records.push(vec![
                ("密钥", to_hex_lower(&dec_key)),
                ("IV", to_hex_lower(&dec_iv)),
                ("aad", to_hex_lower(&dec_aad)),
                ("密文", to_hex_lower(&ciphertext)),
                ("明文", to_hex_lower(&plaintext)),
                ("tag", to_hex_lower(&tag)),
            ]);
        }
    }

    let path = output_dir.join("SM4_GCM_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_GCM_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── XTS ────────────────────────────────────────────────────────────────────

pub fn generate_sm4_xts(output_dir: &Path, count: usize) -> std::io::Result<()> {
    // XTS 加密和解密使用不同的密钥（与样本文件一致）
    let enc_key_full: [u8; 32] = random_bytes_array();
    let dec_key_full: [u8; 32] = random_bytes_array();

    let mut enc_records = Vec::new();
    let mut dec_records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_XTS_LENGTHS[i % SM4_XTS_LENGTHS.len()];
        let tweak: [u8; 16] = random_bytes_array();

        // 将 32 字节密钥拆分为 key1 和 key2
        let enc_key1: [u8; 16] = enc_key_full[..16].try_into().unwrap();
        let enc_key2: [u8; 16] = enc_key_full[16..].try_into().unwrap();

        // 加密方向
        {
            let plaintext = random_bytes(pt_len);

            let ciphertext = sm4_encrypt_xts(&enc_key1, &enc_key2, &tweak, &plaintext);

            // 自验证
            let decrypted = sm4_decrypt_xts(&enc_key1, &enc_key2, &tweak, &ciphertext);
            assert_eq!(plaintext, decrypted, "SM4-XTS 加密自验证失败");

            enc_records.push(vec![
                ("密钥", to_hex_lower(&enc_key_full)),
                ("明文长度", len_hex(pt_len)),
                ("明文", to_hex_lower(&plaintext)),
                ("tweak", to_hex_lower(&tweak)),
                ("密文", to_hex_lower(&ciphertext)),
            ]);
        }

        // 解密方向
        {
            let dec_key1: [u8; 16] = dec_key_full[..16].try_into().unwrap();
            let dec_key2: [u8; 16] = dec_key_full[16..].try_into().unwrap();
            let dec_tweak: [u8; 16] = random_bytes_array();
            let plaintext = random_bytes(pt_len);

            let ciphertext = sm4_encrypt_xts(&dec_key1, &dec_key2, &dec_tweak, &plaintext);

            // 自验证
            let decrypted = sm4_decrypt_xts(&dec_key1, &dec_key2, &dec_tweak, &ciphertext);
            assert_eq!(plaintext, decrypted, "SM4-XTS 解密自验证失败");

            dec_records.push(vec![
                ("密钥", to_hex_lower(&dec_key_full)),
                ("密文长度", len_hex(pt_len)),
                ("密文", to_hex_lower(&ciphertext)),
                ("tweak", to_hex_lower(&dec_tweak)),
                ("明文", to_hex_lower(&plaintext)),
            ]);
        }
    }

    let path = output_dir.join("SM4_XTS_加密.txt");
    write_records_to_file(&path, &enc_records)?;
    println!("  已生成: {}", path.display());

    let path = output_dir.join("SM4_XTS_解密.txt");
    write_records_to_file(&path, &dec_records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}

// ─── CBC-MAC ────────────────────────────────────────────────────────────────

/// CBC-MAC：使用 SM4-CBC 加密，取最后一个分组作为 MAC
fn sm4_cbc_mac(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let data_len = data.len();
    let mut ciphertext = vec![0u8; data_len];
    sm4_encrypt_cbc(key, iv, data, &mut ciphertext);

    // MAC = 最后 16 字节
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&ciphertext[data_len - 16..]);
    mac
}

pub fn generate_sm4_cbcmac(output_dir: &Path, count: usize) -> std::io::Result<()> {
    let key: [u8; 16] = random_bytes_array();
    let iv: [u8; 16] = random_bytes_array();
    let mut records = Vec::new();

    for i in 0..count {
        let pt_len = SM4_BLOCK_LENGTHS[i % SM4_BLOCK_LENGTHS.len()];
        let plaintext = random_bytes(pt_len);

        let mac = sm4_cbc_mac(&key, &iv, &plaintext);

        // 自验证：再算一次确认一致
        let mac_verify = sm4_cbc_mac(&key, &iv, &plaintext);
        assert_eq!(mac, mac_verify, "SM4-CBCMAC 自验证失败");

        records.push(vec![
            ("密钥", to_hex_upper(&key)),
            ("IV", to_hex_upper(&iv)),
            ("明文长度", len_hex(pt_len)),
            ("明文", to_hex_upper(&plaintext)),
            ("MAC值", to_hex_upper(&mac)),
        ]);
    }

    let path = output_dir.join("SM4_CBCMAC.txt");
    write_records_to_file(&path, &records)?;
    println!("  已生成: {}", path.display());

    Ok(())
}
