use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// 一条测试向量记录（键值对）
pub type Record = HashMap<String, String>;

/// 解析测试向量文件，返回多组记录
/// 文件格式: 每行 `key= value`，记录之间用空行分隔
pub fn parse_file(path: &Path) -> Result<Vec<Record>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("读取文件失败 {}: {}", path.display(), e))?;
    parse_content(&content)
}

/// 解析文件内容字符串
fn parse_content(content: &str) -> Result<Vec<Record>, String> {
    let mut records = Vec::new();
    let mut current = Record::new();

    for line in content.lines() {
        let line = line.trim_end_matches('\r').trim();

        if line.is_empty() {
            if !current.is_empty() {
                records.push(current);
                current = Record::new();
            }
            continue;
        }

        // 解析 "key= value" 格式
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            current.insert(key, value);
        } else {
            return Err(format!("无法解析行: {}", line));
        }
    }

    // 最后一组（文件末尾可能没有空行）
    if !current.is_empty() {
        records.push(current);
    }

    Ok(records)
}

/// 从记录中获取必需字段，不存在则返回错误
pub fn get_field<'a>(record: &'a Record, key: &str) -> Result<&'a str, String> {
    record
        .get(key)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("缺少字段: {}", key))
}

/// 将 HEX 字符串解码为字节数组
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| format!("HEX 解码失败 '{}': {}", hex_str, e))
}

/// 将 HEX 字符串解码为固定大小数组
pub fn hex_to_array<const N: usize>(hex_str: &str) -> Result<[u8; N], String> {
    let bytes = hex_to_bytes(hex_str)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("长度不匹配: 期望 {} 字节, 实际 {} 字节", N, v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content() {
        let content = "密钥= AABB\n明文= 1122\n\n密钥= CCDD\n明文= 3344\n";
        let records = parse_content(content).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["密钥"], "AABB");
        assert_eq!(records[1]["明文"], "3344");
    }
}
