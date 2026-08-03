<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="resources/logo.png">
    <source media="(prefers-color-scheme: light)" srcset="resources/logo-dark.png">
    <img alt="Apex" src="resources/logo.png" width="75%">
  </picture>
</div>

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Apex Cipher Version](https://img.shields.io/badge/Apex_Cipher-26.07-blue)](https://github.com/is-nobody/apex-lang)
![Available](https://img.shields.io/badge/Available-Windows%20%7C%20macOS%20%7C%20Linux-red)

This is the official repository for [Apex](https://github.com/is-nobody/apex-cipher) Cipher.

## Why Apex Cipher?
- **Secure by Design:** Implements a 10-round SPN cipher with S-box substitution, key expansion, and CBC mode for robust encryption.

- **Authenticated Encryption:** HMAC-SHA256 ensures data integrity and authenticity, protecting against tampering.

- **Simple Interface:** Provides `cipher_encrypt` and `cipher_decrypt` functions with automatic IV generation and padding.

- **Memory Safety:** Uses `secure_zero` to clear sensitive data from memory after use.

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
Welcome to Apex Cipher!
Max text: 16384 bytes | Key: up to 64 bytes
Cipher: 10-round SPN + CBC + HMAC | Format: Base64
Key: 1e7bf8c41bc9b6935f3c14fc8516ab7cd2ef18b94f07d9cd7ca493807284c85b (32 bytes)

1. Encrypt
2. Decrypt
3. Set key
> 1
Enter text: account password: pass911 
Encrypted (84 bytes):
wXsFvxTfOug3VODqiIAFbxoAAABcozU7py+YoP2nOPLDmkpwMCit2G2KFons03eun4//1+UngSIkYvZOvDC4NMhO6q25AkgelY1GClHwbkKINA2R
```

### File Encryption
When you need to work with files, use the `encode` and `decode` arguments:

```bash
none@root:~$ apex-cipher encode main.c mykey123
Key: 6d796b6579313233 (8 bytes)
Successfully encrypted: main.enc (10057 bytes)

none@root:~$ apex-cipher decode main.enc mykey123
Key: 6d796b6579313233 (8 bytes)
Successfully decrypted: main.dec (7475 bytes)
```

## Security Features
- **10 Rounds:** Provides sufficient diffusion and confusion for symmetric encryption.

- **CBC Mode:** Each block XORed with previous ciphertext for semantic security.

- **HMAC-SHA256:** 32-byte authentication tag to verify integrity.

- **Random IV:** Unique initialization vector for each encryption operation.

- **Constant-Time Comparison:** `ct_memcmp` prevents timing attacks.

- **Secure Zeroization:** Sensitive data cleared from memory after use.

## Getting Help
See [Issues](https://github.com/is-nobody/apex-cipher/issues) for bug reports and feature requests.

## Contributing
Apex Cipher is created and maintained by one person, but contributions are welcome!

Please see [contributing](contributing.md) and remember about [Code of Conduct](code_of_conduct.md)

## License
Apex Cipher is distributed under the terms of the **MIT license**.

See [license](license) for details.