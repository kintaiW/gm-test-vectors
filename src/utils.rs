use rand::RngCore;

/// 生成指定长度的随机字节
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// 生成指定长度的随机字节（固定大小数组）
pub fn random_bytes_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// 字节数组转大写 HEX 字符串
pub fn to_hex_upper(data: &[u8]) -> String {
    hex::encode_upper(data)
}

/// 字节数组转小写 HEX 字符串
pub fn to_hex_lower(data: &[u8]) -> String {
    hex::encode(data)
}

/// 将长度编码为 8 位大写 HEX（如 0x10 -> "00000010"）
pub fn len_hex(len: usize) -> String {
    format!("{:08X}", len)
}
