# 🔐 Image Security by Triple DES (3DES) - Improved Implementation

**PROJECT GOAL: ENCRYPTION & DECRYPTION of IMAGES through an Authenticated, Multi-Layered Triple DES Architecture.**

This repository contains a final-year engineering project that implements a highly secure image encryption and decryption system. It builds upon the foundational concepts of the Triple Data Encryption Standard (3DES) but heavily modifies the cryptographic architecture to eliminate vulnerabilities found in standard open-source implementations (such as MD5 key hashing and static nonces).

---

## 📖 Theoretical Background: Data Encryption Standard (DES) & 3DES

### Why DES is no longer enough
The original Data Encryption Standard (DES) uses a 56-bit key to encrypt plaintext. With the rise of modern computing power, a 56-bit key space can easily be cracked using brute-force attacks in a matter of hours. To prevent this, Double DES and Triple DES were introduced, offering much higher security by utilizing 112-bit and 168-bit keys, respectively.

### How Triple DES (3DES) Works
In cryptography, Triple DES (officially the Triple Data Encryption Algorithm) is a symmetric-key block cipher that applies the DES cipher algorithm three times to each data block.

* **Block sizes:** 64 bits
* **Key sizes:** 168, 112, or 56 bits (keying options 1, 2, and 3, respectively)

Triple-DES encryption uses a triple-length DATA key comprised of three 8-byte DES keys to encipher 8 bytes of data using the following method:
1. **Encipher** the data using the first key.
2. **Decipher** the result using the second key.
3. **Encipher** the second result using the third key.

To decipher data that has been Triple-DES enciphered, the procedure is reversed:
1. **Decipher** the data using the third key.
2. **Encipher** the result using the second key.
3. **Decipher** the second result using the first key.

![Triple DES Architecture](https://user-images.githubusercontent.com/28294942/116646664-43a4e280-a996-11eb-9624-fbac40d50855.jpg)

---

## 🚀 Novelty & Security Improvements (Our Upgrades)

While the base concept of 3DES is sound, many standard Python implementations use weak key derivation methods and fail to ensure file integrity. **We completely overhauled the cryptographic pipeline to meet modern security standards:**

1. **Secure Key Derivation (PBKDF2-HMAC-SHA256):** We replaced the highly vulnerable, collision-prone MD5 hashing algorithm. Our system uses PBKDF2 with 600,000 iterations and generates a fresh 16-byte random salt per encryption. Dictionary and brute-force attacks become computationally prohibitive.
2. **Randomized Nonces:** Base implementations often use a hardcoded fixed nonce (e.g., `b'0'`), which catastrophically breaks encryption modes. Our version generates a fresh 8-byte cryptographically secure random nonce for every operation.
3. **Authenticated Encryption (EAX Mode):** We upgraded the cipher to use 3DES in EAX mode (combining CTR-mode encryption with OMAC authentication). It generates a 16-byte authentication tag that ensures any file tampering or incorrect passwords result in an immediate rejection with zero plaintext leaked.
4. **Atomic File Write Safety:** Standard implementations directly overwrite the original image file during encryption, risking permanent data loss if the system crashes mid-write. We implemented an atomic write mechanism: outputs are written to a temporary file first and only replace the original upon a 100% successful operation.
5. **Structured File Format:** Encrypted files now utilize a deterministic, forward-compatible header format: 
   `[SALT 16B] | [NONCE 8B] | [TAG 16B] | [CIPHERTEXT]`

---

## ⚙️ System Architecture & Workflow

The proposed image encryption system follows a strict 5-phase pipeline:

1. **Phase 1: Key Derivation** -> User Passphrase + Random Salt -> PBKDF2 -> 24-byte 3DES Key.
2. **Phase 2: Cipher Initialization** -> `DES3.new` in EAX Mode with a Random Nonce.
3. **Phase 3: Encryption** -> Raw image bytes are encrypted and an Authentication Tag is digested.
4. **Phase 4: Safe File Write** -> Data is written to a `.tmp` file and atomically swapped with the original file.
5. **Phase 5: Decryption** -> Header is parsed, key is re-derived, tag is verified, and plaintext is safely restored.

![Project Flowchart](https://user-images.githubusercontent.com/28294942/116644568-5a950600-a991-11eb-8374-87260c38ff41.jpg)

---

## 📊 Feature Comparison: Base vs. Improved Implementation

| Security Property | Standard Base Project | Our Improved Implementation |
| :--- | :--- | :--- |
| **Key Derivation** | MD5 (Cryptographically broken) | PBKDF2-HMAC-SHA256 (600K iterations) |
| **Salt Generation**| None | 16-byte random salt per encryption |
| **Nonce Usage** | Fixed (`b'0'`) | 8-byte cryptographic random nonce |
| **Encryption Mode**| Standard EAX / ECB | EAX (Strictly Authenticated) |
| **Integrity Check**| None | 16-byte authentication tag |
| **File Safety** | Direct overwrite (Risk of data loss)| Atomic temp-file replace |
| **Tamper Detection**| No | Yes (Verification on decrypt) |

---

## 💻 Installation & Dependencies

This implementation requires **Python 3.8+**. 

Install the required cryptographic and plotting libraries using pip:
```bash
pip install pycryptodome matplotlib