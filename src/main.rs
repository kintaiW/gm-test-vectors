mod format;
mod generators;
mod parser;
mod utils;
mod verifiers;

use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gm-testgen")]
#[command(about = "国密算法正确性测试样本生成与验证工具")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 生成测试向量
    Generate {
        /// 算法类型: sm2, sm3, sm4, all
        #[arg(long, default_value = "all")]
        algo: String,

        /// 每类测试向量的数量
        #[arg(long, default_value_t = 10)]
        count: usize,

        /// 输出目录
        #[arg(long, default_value = "./output")]
        output: PathBuf,
    },
    /// 验证测试向量
    Verify {
        /// 测试向量文件夹路径
        #[arg(long)]
        input: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { algo, count, output } => {
            println!("gm-testgen 国密测试样本生成器");
            println!("算法: {}, 数量: {}, 输出: {}", algo, count, output.display());
            println!("---");

            let result = match algo.as_str() {
                "sm2" => generate_sm2(&output, count),
                "sm3" => generate_sm3(&output, count),
                "sm4" => generate_sm4(&output, count),
                "all" => generate_all(&output, count),
                other => {
                    eprintln!("未知算法: {}（支持: sm2, sm3, sm4, all）", other);
                    std::process::exit(1);
                }
            };

            match result {
                Ok(()) => println!("---\n全部生成完毕!"),
                Err(e) => {
                    eprintln!("生成失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Verify { input } => {
            println!("gm-testgen 国密测试样本验证器");
            println!("输入目录: {}", input.display());
            println!("---");

            match run_verify(&input) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("验证失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

// ─── 生成相关 ────────────────────────────────────────────────────────────────

fn generate_sm2(output_dir: &PathBuf, count: usize) -> std::io::Result<()> {
    println!("[SM2] 生成加密/解密测试向量...");
    generators::sm2::generate_sm2_encrypt(output_dir, count)?;
    println!("[SM2] 生成签名/验签测试向量...");
    generators::sm2::generate_sm2_sign(output_dir, count)?;
    Ok(())
}

fn generate_sm3(output_dir: &PathBuf, count: usize) -> std::io::Result<()> {
    println!("[SM3] 生成哈希测试向量...");
    generators::sm3::generate_sm3(output_dir, count)?;
    println!("[SM3] 生成 HMAC 测试向量...");
    generators::sm3::generate_sm3_hmac(output_dir, count)?;
    Ok(())
}

fn generate_sm4(output_dir: &PathBuf, count: usize) -> std::io::Result<()> {
    println!("[SM4] 生成 ECB 测试向量...");
    generators::sm4::generate_sm4_ecb(output_dir, count)?;
    println!("[SM4] 生成 CBC 测试向���...");
    generators::sm4::generate_sm4_cbc(output_dir, count)?;
    println!("[SM4] 生成 CFB 测试向量...");
    generators::sm4::generate_sm4_cfb(output_dir, count)?;
    println!("[SM4] 生成 OFB 测试向量...");
    generators::sm4::generate_sm4_ofb(output_dir, count)?;
    println!("[SM4] 生成 CTR 测试向量...");
    generators::sm4::generate_sm4_ctr(output_dir, count)?;
    println!("[SM4] 生成 GCM 测试向量...");
    generators::sm4::generate_sm4_gcm(output_dir, count)?;
    println!("[SM4] 生成 XTS 测试向量...");
    generators::sm4::generate_sm4_xts(output_dir, count)?;
    println!("[SM4] 生成 CBC-MAC 测试向量...");
    generators::sm4::generate_sm4_cbcmac(output_dir, count)?;
    Ok(())
}

fn generate_all(output_dir: &PathBuf, count: usize) -> std::io::Result<()> {
    generate_sm2(output_dir, count)?;
    generate_sm3(output_dir, count)?;
    generate_sm4(output_dir, count)?;
    Ok(())
}

// ─── 验证相关 ────────────────────────────────────────────────────────────────

fn run_verify(input_dir: &PathBuf) -> Result<(), String> {
    if !input_dir.is_dir() {
        return Err(format!("路径不是目录: {}", input_dir.display()));
    }

    let mut entries: Vec<_> = std::fs::read_dir(input_dir)
        .map_err(|e| format!("读取目录失败: {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "txt")
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        return Err("目录中没有 .txt 文件".to_string());
    }

    let mut total_files = 0;
    let mut passed_files = 0;
    let mut total_records = 0;
    let mut passed_records = 0;
    let mut skipped_files = Vec::new();

    for entry in &entries {
        let path = entry.path();
        match verifiers::verify_file(&path) {
            Ok((passed, total)) => {
                total_files += 1;
                total_records += total;
                passed_records += passed;
                let status = if passed == total { "PASS" } else { "FAIL" };
                if passed == total {
                    passed_files += 1;
                }
                println!("  [{}] {} ({}/{})", status, path.file_name().unwrap().to_string_lossy(), passed, total);
            }
            Err(e) => {
                if e.contains("无法识别文件类型") {
                    skipped_files.push(path.file_name().unwrap().to_string_lossy().to_string());
                } else {
                    total_files += 1;
                    println!("  [ERR] {}: {}", path.file_name().unwrap().to_string_lossy(), e);
                }
            }
        }
    }

    println!("---");
    println!("验证结果: {}/{} 文件通过, {}/{} 条记录通过",
        passed_files, total_files, passed_records, total_records);

    if !skipped_files.is_empty() {
        println!("跳过（无法识别）: {}", skipped_files.join(", "));
    }

    if passed_files == total_files && passed_records == total_records {
        println!("全部验证通过!");
        Ok(())
    } else {
        Err(format!("部分验证失败: {}/{} 文件, {}/{} 记录",
            total_files - passed_files, total_files,
            total_records - passed_records, total_records))
    }
}
