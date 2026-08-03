<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="resources/logo.png">
    <source media="(prefers-color-scheme: light)" srcset="resources/logo-dark.png">
    <img alt="Apex" src="resources/logo.png" width="75%">
  </picture>
</div>

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Apex Cipher Version](https://img.shields.io/badge/Apex_Cipher-26.08-blue)](https://github.com/is-nobody/apex-cipher)
![Available](https://img.shields.io/badge/Available-Windows%20%7C%20macOS%20%7C%20Linux-red)

This is the official repository for [Apex](https://github.com/is-nobody/apex-cipher) Cipher.

## Why Apex Cipher?
- **Minimal & Lightweight:** Pure C implementation with zero external dependencies and minimal codebase.

- **Authenticated Encryption:** HMAC-SHA256 integrity verification detects any tampering or corruption.

- **Streaming Support:** Encrypts and decrypts large files in chunks without loading everything into memory.

- **Memory Safe:** Secure zeroization wipes sensitive keys and data immediately after use.

## Quick Start
### Install Apex Cipher
1. Clone the repository:
```bash
git clone https://github.com/is-nobody/apex-cipher.git
cd apex-cipher
```

2. Build the project:
```bash
cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release
cmake --build build/ --parallel
```

3. Run the REPL:
```bash
./build/apex-cipher
```

**Now you're in REPL!**

### Testing the Cipher
From the REPL, encrypt a message:

```bash
Welcome to Apex Cipher 26.08!
Max text in REPL: 16384 bytes | Key: up to 64 bytes
Key: 70b4865d7d09b6cf4207b20cbedcb14bc42847b3af8a2edc0a73687b7ed368f8 (32 bytes)

1. Encrypt
2. Decrypt
3. Set key
> 1
Enter text: account password: pass911 
Encrypted (84 bytes):
663ef7d6144d8bc3a90ff43e52e73e171a0000007c695b6eb313e67fd516018753640343f94815959e8dffcaad64354ec18d0975772c67a945bfd140a41461e1014012e9a79216e53d84f3d6596b24b80624efc6
```

### File Encryption
When you need to work with files, use the `encode` and `decode` arguments:

```bash
none@root:~$ apex-cipher encode main.c mykey123
Key: 6d796b6579313233 (8 bytes)
Progress: 100.0% (6123 / 6123 bytes)
Successfully encrypted: main.enc

none@root:~$ apex-cipher decode main.enc mykey123
Key: 6d796b6579313233 (8 bytes)
Progress: 100.0% (6123 / 6123 bytes)
Successfully decrypted: main.dec
```

## Security Features
- **10 Rounds:** Provides sufficient diffusion and confusion for symmetric encryption.

- **CBC Mode:** Each block XORed with previous ciphertext for semantic security.

- **HMAC-SHA256:** 32-byte authentication tag to verify integrity (Encrypt-then-MAC).

- **Random IV:** Unique initialization vector for each encryption operation.

- **KDF with Salt:** 100,000 PBKDF2-HMAC-SHA256 iterations for password-based keys.

- **Constant-Time Comparison:** `ct_memcmp` prevents timing attacks on MAC verification.

- **Secure Zeroization:** Sensitive keys and intermediate state explicitly wiped after use.

## Getting Help
See [Issues](https://github.com/is-nobody/apex-cipher/issues) for bug reports and feature requests.

## Contributing
Apex Cipher is created and maintained by one person, but contributions are welcome!

Please see [contributing](contributing.md) and remember about [Code of Conduct](code_of_conduct.md)

## License
Apex Cipher is distributed under the terms of the **MIT license**.

See [license](license) for details.