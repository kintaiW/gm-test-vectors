# gm-testgen

国密算法（SM2/SM3/SM4）正确性测试样本生成与验证工具。

基于 [gm-sdk-rs](https://github.com/kintaiW/gm-sdk-rs) 密码库，生成标准格式的测试向量文件，并支持对已有样本进行反向验证。

> **WARNING**: 本项目仅供学习和开发测试使用，请勿用于商用密码产品送检现场测试。

## 功能

- **生成测试向量**：调用 gm-sdk-rs 的加密/签名 API，随机生成测试数据，经过"生成-自验证"循环后输出
- **验证测试向量**：读取指定目录下的测试向量文件，自动识别文件类型，调用对应的密码算法进行正确性验证

### 支持的算法和模式

| 算法 | 模式 | 生成的文件 |
|------|------|-----------|
| SM2 | 加密/解密 | `SM2_加密_N（解密格式）.txt`, `SM2_解密_N.txt` |
| SM2 | 签名/验签（预处理后） | `SM2验签_预处理后_N.txt`, `SM2签名_预处理后_N（验签格式）.txt` |
| SM3 | 哈希 | `SM3_N.txt` |
| SM3 | HMAC | `SM3_HMAC_N.txt` |
| SM4 | ECB | `SM4_ECB_加密.txt`, `SM4_ECB_解密.txt` |
| SM4 | CBC | `SM4_CBC_加密.txt`, `SM4_CBC_解密.txt` |
| SM4 | CFB | `SM4_CFB_加密.txt`, `SM4_CFB_解密.txt` |
| SM4 | OFB | `SM4_OFB_加密.txt`, `SM4_OFB_解密.txt` |
| SM4 | CTR | `SM4_CTR_加密.txt`, `SM4_CTR_解密.txt` |
| SM4 | GCM | `SM4_GCM_加密.txt`, `SM4_GCM_解密.txt` |
| SM4 | XTS | `SM4_XTS_加密.txt`, `SM4_XTS_解密.txt` |
| SM4 | CBC-MAC | `SM4_CBCMAC.txt` |

## 构建

```bash
cargo build --release
```

> 需要 SSH 访问 GitHub 以拉取 gm-sdk-rs 依赖。

## CLI 用法

### 生成测试向量

```bash
# 生成全部算法的测试向量（默认 10 组，输出到 ./output）
gm-testgen generate

# 指定算法、数量和输出目录
gm-testgen generate --algo sm4 --count 20 --output ./my-vectors

# 仅生成 SM2 测试向量
gm-testgen generate --algo sm2
```

参数说明：
- `--algo`：算法类型，可选 `sm2`, `sm3`, `sm4`, `all`（默认 `all`）
- `--count`：每类测试向量的数量（默认 `10`）
- `--output`：输出目录（默认 `./output`）

### 验证测试向量

```bash
# 验证指定目录下的所有测试向量文件
gm-testgen verify --input ./output

# 验证其他来源的样本
gm-testgen verify --input ./samples
```

参数说明：
- `--input`：包含测试向量 `.txt` 文件的目录路径

验证器会根据文件名自动识别算法和模式，逐条验证每个记录的正确性，并输出统计结果。

## 文件格式

测试向量文件采用 `key= value` 纯文本格式，记录之间用空行分隔：

```
密钥= 5587062E39AFE9A9554D4C4E3BA6632E
明文长度= 00000010
明文= 000B19036EE415A78F9C4A671E6A7192
密文= 09C0D4B85DEC824FABB92C5691AD90FB

密钥= 5587062E39AFE9A9554D4C4E3BA6632E
明文长度= 00000020
明文= 12B1CD439861A25DD91D6E785B79BD4D...
密文= B0562B25280019CB72EEFDC64A40A56E...
```

- 数值均为十六进制编码
- SM4 GCM/XTS 模式使用小写 hex，其余使用大写 hex
- 长度字段为 8 位十六进制（如 `00000010` 表示 16 字节）

## CI/CD

项目使用 GitHub Actions 实现全自动构建和发布。

**CI**（`.github/workflows/ci.yml`）：每次推送到 `main` 或提交 PR 时自动运行 build + test。

**Release**（`.github/workflows/release.yml`）：推送 `v*` 标签时自动触发，并行编译 4 个平台的 release 二进制，打包后发布到 GitHub Releases。

```bash
# 发布流程
git tag v0.1.0
git push --tags
```

发布的平台和产物：

| 平台 | Target | 产物 |
|------|--------|------|
| Linux x64 | `x86_64-unknown-linux-gnu` | `gm-testgen-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x64 | `x86_64-pc-windows-msvc` | `gm-testgen-vX.Y.Z-x86_64-pc-windows-msvc.zip` |
| macOS x64 | `x86_64-apple-darwin` | `gm-testgen-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS ARM | `aarch64-apple-darwin` | `gm-testgen-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
