# ZIF (ZIF Is File-vault)

**ZIF** is a zero-dependency command-line utility written in Go that compresses and encrypts files or directories into a single `.zif` vault. It is powered by **E27**, an experimental, Enigma-inspired 512-bit cryptographic permutation operating in a sponge/duplex mode for authenticated encryption, paired with a custom memory-hard key derivation function.

> ⚠️ **CRITICAL SECURITY DISCLAIMER**
>
>
>
> **E27 is a non-standard, home-grown cryptographic construction that has NOT been peer-reviewed or independently audited.**
>
>
>
> - **Do NOT use ZIF/E27 to protect sensitive, financial, medical, legal, or production data.** For real-world security needs, please use battle-tested, standardized tools such as [`age`](https://github.com/FiloSottile/age), `GnuPG`, or `7-Zip` (AES-256).
> - **Configuration Space**=**Security:** While E27 boasts a nominal key configuration space of ≈247,495, its generic security is bounded at ≈2128 by its 256-bit sponge capacity, and its practical security relies heavily on user password entropy and key-file separation.
> - This project was developed for **applied cryptography research, systems engineering, and educational purposes**.

## 📖 Overview & Architecture

Unlike standard archive tools that expose filenames and directory structures prior to extraction, ZIF archives and compresses data using **Deflate (ZIP)** *before* encrypting the stream in **64 KiB chunks**.

```
[Source File / Folder] ──▶ [ZIP Archive (Deflate)] ──▶ [64 KiB Chunker] ──▶ [E27 Duplex AEAD] ──▶ [Vault (.zif)]
                                                                                   ▲
[Password + 16B Salt]  ──▶ [E27-KDF/2 (32 MiB RAM)] ──▶ [512-bit Session Key K] ───┘
                                                                 ▲
[Random Key (7,222 B)] ──▶ [E27 Permutation Core (27 Rotors + Plugboard)] ◀── [Key File (.zifkey.txt)]
```

### Key Features

- **Zero External Dependencies:** Built purely using the Go standard library (`archive/zip`, `crypto/rand`, `crypto/subtle`, etc.). Compiles into a single cross-platform binary.
- **Two-Factor Offline Design:** Separates the encrypted container (`<stem>.zif`) from the random Enigma key configuration (`<stem>.zifkey.txt`). Without the key file, offline password brute-forcing against the vault is impossible.
- **Memory-Hard Key Derivation (`E27-KDF/2`):** Inspired by `scrypt`'s ROMix pattern, defaulting to **32 MiB** (219 blocks) and 1,048,576 permutation calls (≈1.75s per guess on a single CPU thread).
- **Hardened File Extraction & I/O:**
   - Full multi-chunk tag verification (`subtle.ConstantTimeCompare`) before releasing any plaintext.
   - Buffered random-access chunk reading (`io.ReaderAt`) keeping runtime RAM overhead minimal (2×64 KiB buffers).
   - Built-in defenses against **Zip-Slip** path traversal, **symlink** following, and accidental file overwrites.
   - Atomic writes (`.tmp` + rename) with automatic rollback on failure.

## 🔬 The E27 Algorithm

E27 translates the mechanical concepts of the classical WWII **Enigma machine** into a modern 512-bit Substitution-Permutation Network (SPN) operating over bytes (GF(28) with irreducible polynomial `0x11D`):

1. **Plugboard Layer (**P**):** A key-dependent 256-byte bijective substitution applied before the first round and after the final round.
2. **27 Virtual Rotors:** Each round r∈{0..26} uses a distinct effective S-box derived via cyclic offset rotation:
   Sr​(x)=rotr​[(x+or​)mod256]−or​(mod256)
   Every generated rotor is filtered during key generation to guarantee **Differential Uniformity (**DU≤10**)** and **Nonlinearity (**NL≥94**)**.
3. **Diagonal Shift & Circulant MDS Diffusion:** Byte transposition followed by an 8×8 circulant Maximum Distance Separable (MDS) matrix (`[1, 1, 4, 1, 8, 5, 2, 9]`, adopted from Whirlpool) with an optimal **branch number of 9** (all 12,869 square submatrices verified invertible). Full 512-bit avalanche is achieved within **2 rounds**.
4. **Sponge/Duplex AEAD:** Operates on a 512-bit state (r=256-bit rate, c=256-bit capacity), authenticating each 64 KiB chunk with a 128-bit tag bound to the chunk counter and final-chunk flag to prevent truncation or reordering.

## 📊 Benchmarks & Cryptographic Metrics

Measurements taken on Linux x86-64 (Go 1.24, single thread):

| Metric / Primitive | E27 / ZIF | Industry Standard Comparison |
| --- | --- | --- |
| **Nominal Key Space** | ≈247,495 (≈1014,297) | Enigma M3: ≈267 \| AES-256: $2^{256 |
| **Generic Security Bound** | ≈128-bit (256-bit capacity) | AES-128: 128-bit \| AES-256: 256-bit |
| **S-box Quality** | DU≤10, NL≥94 (across 27 rotors) | AES S-box: DU=4, NL=112 (1 fixed S-box) |
| **AEAD Throughput** | **14 – 22 MB/s** (1 thread, no SIMD) | AES-256-GCM (AES-NI): ≈11,426 MB/s (~530–800x faster) |
| **KDF Cost (32 MiB)** | **~1.75 seconds** / guess | `scrypt` (32 MiB): ~0.080s \| `Argon2id` (32 MiB): ~0.022s |

### Known Limitations

- **No Hardware Acceleration & Cache-Timing Risk:** Uses 434 KiB of secret-indexed lookup tables (`T-tables`), making it slower than hardware-accelerated ciphers and potentially vulnerable to cache-timing side-channel attacks on shared/multi-tenant hosts.
- **Single-Threaded:** Chunk encryption/decryption is currently sequential, and decryption performs two passes (full verification pass followed by extraction pass).
- **No Minimum Password Policy:** Accepts any non-empty password; users must enforce strong passphrases manually.

## 🚀 Installation & Usage

### Prerequisites & Build

Requires **Go 1.19+**. No third-party packages needed.

```
git clone https://github.com/yourusername/zif.git
cd zif
go build -o zif zif.go
```

### Command Syntax

```
zif -c <source_file_or_dir> -o <output_dir> [-k <key_dir | key_file.txt>]
zif -d <vault.zif | vault_dir> -o <output_dir> [-k <key_file.txt | key_dir>]
zif -t   # Run built-in cryptographic & extraction self-tests
```

### Examples

**1. Encrypt & compress a folder (recommended: save key separately)**

```
./zif -c ./my_documents -o ./vaults -k ./secure_keys
```

*Output:* Creates `./vaults/<random_hex>.zif` and `./secure_keys/<random_hex>.zifkey.txt`.

**2. Decrypt & extract a vault**

```
./zif -d ./vaults/757463a7c59f5ed8.zif -o ./restored -k ./secure_keys/757463a7c59f5ed8.zifkey.txt
```

*(Tip: Omit `-k` during single-file decryption to paste the `---BEGIN ZIF KEY---` block directly into the terminal.)*

**3. Run the built-in self-test suite**

```
./zif -t
```

Verifies MDS invertibility (12,869 submatrices), rotor S-box quality, 4,000-trial avalanche distribution, KDF sensitivity, keystream χ2 randomness, AEAD tamper rejection, and Zip-Slip/symlink defenses.

## 📚 Documentation & Research Paper

A comprehensive 70-page technical monograph (in Indonesian) analyzing the mathematical formalization, configuration-space combinatorics, empirical benchmarks, source-code audit findings, and comparisons with Enigma and modern standards is available in the `docs/` directory:

- [`docs/ZIF_E27.pdf`](https://drive.google.com/file/d/1hYqwFuFbZgL-fYZEq7CKG9ZUtedOYBjN/view?usp=drive_link)

## 🤝 Contributing & Cryptanalysis

Independent cryptanalysis, code reviews, and performance optimizations are warmly welcomed! If you find a differential, linear, integral, algebraic, or implementation flaw in E27 or `zif.go`, please open an **Issue** or submit a **Pull Request**.

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
