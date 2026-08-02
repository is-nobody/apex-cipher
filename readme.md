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
git clone https://github.com/yourusername/apex-cipher.git
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
Max text: 4096 bytes | Key: up to 64 bytes
Cipher: 10-round SPN + CBC + HMAC | Format: Base64
Key: 60a6f975c9d6c8442d607447fb28847870684a59dc887e62e7513b9d623d7b61 (32 bytes)

1. Encrypt
2. Decrypt
3. Set key
4. Exit
> 1
Enter text (empty line to finish):
Hello, Friend!


Original (14 bytes): Hello, Friend!

Encrypted (68 bytes):
1pCFjIfeHWjvpSGN6gzqrg4AAAANr8GaXYVzJtHNJRZohFfHMWu9A5fHi+ksZNMq+xapNlOgwsXC1jOl5sIMNv/hA+s=
Verify (14 bytes): Hello, Friend!
✓ OK
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