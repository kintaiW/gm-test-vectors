# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
cargo build                  # dev build
cargo build --release        # release build
cargo run -- generate --algo all --count 10 --output ./output   # generate all test vectors
cargo run -- generate --algo sm2 --count 20 --output ./vectors  # single algorithm
cargo run -- verify --input ./output                             # verify test vectors
```

Subcommands: `generate` (with `--algo`, `--count`, `--output`) and `verify` (with `--input`).

**Prerequisites**: SSH access to `git@github.com:kintaiW/gm-sdk-rs.git`. Cargo must be configured with `net.git-fetch-with-cli = true` in `~/.cargo/config.toml` if ssh-agent isn't available.

## Architecture

This is a CLI tool (`gm-testgen`) that generates correctness test vectors for Chinese national cryptographic algorithms (SM2/SM3/SM4) using the `gm-sdk-rs` library as its computation engine.

**Core principle**: Generate-then-verify. Every test vector is self-validated (encrypt→decrypt, sign→verify) before being written. Failures cause panics. The underlying `gm-sdk-rs` library is never modified — only called and formatted.

### Key modules

- `generators/sm2.rs` — SM2 encrypt/decrypt + sign/verify (pre-processed `e` format)
- `generators/sm3.rs` — SM3 hash + HMAC-SM3
- `generators/sm4.rs` — SM4 in 8 modes: ECB, CBC, CFB, OFB, CTR, GCM, XTS, CBC-MAC
- `verifiers/mod.rs` — File-type dispatcher: identifies algorithm/mode by filename and routes to verifier
- `verifiers/sm2.rs` — SM2 decrypt + signature verification
- `verifiers/sm3.rs` — SM3 hash + HMAC verification
- `verifiers/sm4.rs` — SM4 all 8 modes verification
- `parser.rs` — Parses `key= value` text format into `HashMap<String, String>` records
- `format.rs` — Writes `key= value` text format with blank-line-separated records
- `utils.rs` — Random byte generation, hex encoding helpers

### Critical conventions

**Crate naming**: The dependency is `gm-sdk-rs` but its lib is named `gm_sdk` (configured in its `[lib]` section). Import as `use gm_sdk::...`, NOT `gm_sdk_rs`.

**SM2 format transforms**: The library uses `[u8; 65]` public keys (with `04` prefix) and `C1||C3||C2` ciphertext (C1 has `04` prefix). Output files strip the `04` prefix, yielding 64-byte public keys and shorter ciphertexts.

**SM2 signing**: Uses pre-computed `e` values (the "预处理后" format). The `sm2_sign_with_e()` wrapper generates random `k` internally and calls `sm2_sign_with_k(e, pri_key, k)` from gm-sdk-rs. Requires `crypto-bigint::U256` for the `k` parameter.

**SM4 CBC-MAC**: Not in gm-sdk-rs public API. Implemented locally via `sm4_encrypt_cbc` and extracting the last 16-byte block.

**Hex case**: GCM and XTS files use lowercase hex; all other files use uppercase hex — matching the reference samples in `samples/`.

### Output format

Output files are plain text with Chinese key names (`密钥=`, `明文=`, `密文=`, etc.). Each file in `output/` corresponds 1:1 to a reference file in `samples/`. For SM4 modes, both `_加密.txt` (encrypt) and `_解密.txt` (decrypt) files are generated — same data, different field ordering.
