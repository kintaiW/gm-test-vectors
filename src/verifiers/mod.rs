pub mod sm2;
pub mod sm3;
pub mod sm4;

use std::path::Path;

use crate::parser::{Record, parse_file};

/// 根据文件名模式识别文件类型并调用对应的验证函数
/// 返回 (passed, total) 或错误
pub fn verify_file(path: &Path) -> Result<(usize, usize), String> {
    let filename = path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("无法获取文件名: {}", path.display()))?;

    let records = parse_file(path)?;
    if records.is_empty() {
        return Err(format!("文件无记录: {}", path.display()));
    }

    dispatch_verify(path, filename, &records)
}

fn dispatch_verify(path: &Path, filename: &str, records: &[Record]) -> Result<(usize, usize), String> {
    // SM3
    if filename.starts_with("SM3_HMAC_") {
        return sm3::verify_sm3_hmac(path, records);
    }
    if filename.starts_with("SM3_") {
        return sm3::verify_sm3(path, records);
    }

    // SM2
    if filename.starts_with("SM2_解密_") || filename.contains("解密格式") {
        return sm2::verify_sm2_decrypt(path, records);
    }
    if filename.starts_with("SM2验签_") || filename.contains("验签格式") {
        return sm2::verify_sm2_sign(path, records);
    }

    // SM4
    if filename.starts_with("SM4_ECB_加密") {
        return sm4::verify_sm4_ecb_encrypt(path, records);
    }
    if filename.starts_with("SM4_ECB_解密") {
        return sm4::verify_sm4_ecb_decrypt(path, records);
    }
    if filename.starts_with("SM4_CBC_加密") {
        return sm4::verify_sm4_cbc_encrypt(path, records);
    }
    if filename.starts_with("SM4_CBC_解密") {
        return sm4::verify_sm4_cbc_decrypt(path, records);
    }
    if filename.starts_with("SM4_CFB_加密") {
        return sm4::verify_sm4_cfb_encrypt(path, records);
    }
    if filename.starts_with("SM4_CFB_解密") {
        return sm4::verify_sm4_cfb_decrypt(path, records);
    }
    if filename.starts_with("SM4_OFB_加密") {
        return sm4::verify_sm4_ofb_encrypt(path, records);
    }
    if filename.starts_with("SM4_OFB_解密") {
        return sm4::verify_sm4_ofb_decrypt(path, records);
    }
    if filename.starts_with("SM4_CTR_加密") {
        return sm4::verify_sm4_ctr_encrypt(path, records);
    }
    if filename.starts_with("SM4_CTR_解密") {
        return sm4::verify_sm4_ctr_decrypt(path, records);
    }
    if filename.starts_with("SM4_GCM_加密") {
        return sm4::verify_sm4_gcm_encrypt(path, records);
    }
    if filename.starts_with("SM4_GCM_解密") {
        return sm4::verify_sm4_gcm_decrypt(path, records);
    }
    if filename.starts_with("SM4_XTS_加密") {
        return sm4::verify_sm4_xts_encrypt(path, records);
    }
    if filename.starts_with("SM4_XTS_解密") {
        return sm4::verify_sm4_xts_decrypt(path, records);
    }
    if filename.starts_with("SM4_CBCMAC") {
        return sm4::verify_sm4_cbcmac(path, records);
    }

    Err(format!("无法识别文件类型: {}", filename))
}
