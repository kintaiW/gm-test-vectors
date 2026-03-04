use std::fmt::Write;
use std::fs;
use std::path::Path;

/// 写入一组键值对记录到文件，记录之间用空行分隔
pub fn write_records_to_file(
    path: &Path,
    records: &[Vec<(&str, String)>],
) -> std::io::Result<()> {
    let mut content = String::new();
    for (i, record) in records.iter().enumerate() {
        for (key, value) in record {
            writeln!(&mut content, "{}= {}", key, value).unwrap();
        }
        if i < records.len() - 1 {
            writeln!(&mut content).unwrap();
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}
