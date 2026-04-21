# -*- coding: utf-8 -*-
"""IMAGE ENCRYPTION & DECRYPTION USING ECC (ECIES)

IMAGE SECURITY SYSTEM FOR ARMY, POLICE & SECURE COMMUNICATION

This script provides secure image encryption and decryption using
Elliptic Curve Integrated Encryption Scheme (ECIES) with AES-256-EAX.

How it works:
  - A password is turned into an ECC private key on the NIST P-256 curve
    via PBKDF2.
  - An ephemeral ECC key pair is generated per encryption.
  - ECDH (Elliptic Curve Diffie-Hellman) produces a shared secret which
    is expanded via HKDF into a 256-bit AES key.
  - The image is then encrypted with AES-256 in EAX authenticated mode.

Security features:
  1. PBKDF2 key derivation (600 000 iterations)
  2. Fresh ephemeral key + random nonce per encryption
  3. Authentication tag verification on decryption
  4. Safe file overwriting via temporary files

Dependencies:
  pip install pycryptodome matplotlib psutil
"""

import os
import sys
import shutil
import time
import tempfile
import tracemalloc
import hashlib
import getpass

import psutil
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SALT_SIZE = 16              # bytes – unique per encryption
NONCE_SIZE = 16             # bytes – AES-EAX 128-bit nonce
TAG_SIZE = 16               # bytes – AES-EAX authentication tag
EPH_PUB_SIZE = 64           # bytes – ephemeral public key (32-byte X + 32-byte Y)
KDF_ITERATIONS = 600_000    # PBKDF2 iteration count (OWASP recommendation)
AES_KEY_SIZE = 32           # bytes – AES-256

# NIST P-256 curve order
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# File layout: SALT (16) | EPH_PUB (64) | NONCE (16) | TAG (16) | CIPHERTEXT

HEADER_SIZE = SALT_SIZE + EPH_PUB_SIZE + NONCE_SIZE + TAG_SIZE  # 112 bytes


# ---------------------------------------------------------------------------
# Helper – Display an image
# ---------------------------------------------------------------------------
def imgdis(path):
    """
    Display an image using matplotlib.

    Parameter:
        path : str – Absolute or relative path to an image file.
    """
    img = mpimg.imread(path)
    plt.imshow(img)
    plt.axis("off")
    plt.title(os.path.basename(path))
    plt.show()


# ---------------------------------------------------------------------------
# Key derivation – password → ECC private key via PBKDF2
# ---------------------------------------------------------------------------
def derive_ecc_key(password: str, salt: bytes):
    """
    Derive a NIST P-256 ECC key pair from *password* using PBKDF2-HMAC-SHA256.

    The 32 bytes produced by PBKDF2 are interpreted as a big-endian integer
    and reduced modulo the curve order to obtain a valid private scalar.

    Parameters:
        password : str   – The user's secret passphrase.
        salt     : bytes – A random salt (must be stored alongside ciphertext).

    Returns:
        EccKey – A PyCryptodome ECC key object (private + public).
    """
    key_bytes = PBKDF2(
        password,
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )
    # Convert to a valid private scalar in [1, n-1]
    d = int.from_bytes(key_bytes, "big") % P256_ORDER
    if d == 0:
        d = 1  # Astronomically unlikely, but handled for correctness
    return ECC.construct(curve="P-256", d=d)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
def encrypt(password: str, path: str) -> str:
    """
    Encrypt an image file in-place using ECIES (ECC + AES-256-EAX).

    Workflow:
      1. Derive an ECC key pair from the password (PBKDF2).
      2. Generate a fresh ephemeral ECC key pair.
      3. ECDH  → shared secret  → HKDF  → 256-bit AES key.
      4. AES-EAX encrypt the image; produce an authentication tag.
      5. Store SALT | EPH_PUB | NONCE | TAG | CIPHERTEXT.

    Parameters:
        password : str – The user's secret passphrase.
        path     : str – Path to the image file to encrypt.

    Returns:
        str – The path to the encrypted file (same as *path*).
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Image file not found: {path}")

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    tracemalloc.start()
    cpu_times_start = process.cpu_times()
    t_total_start = time.perf_counter()

    # Read the original image data
    with open(path, "rb") as f:
        plaintext = f.read()

    file_size = len(plaintext)

    # Generate fresh cryptographic material
    salt = get_random_bytes(SALT_SIZE)

    # --- Key derivation (PBKDF2 → ECC key) ---
    t_kdf_start = time.perf_counter()
    password_key = derive_ecc_key(password, salt)
    t_kdf_end = time.perf_counter()

    # Ephemeral ECC key pair (fresh per encryption)
    eph_key = ECC.generate(curve="P-256")

    # ECDH: shared_point = password_pub * eph_priv
    shared_point = password_key.pointQ * int(eph_key.d)
    shared_x = int(shared_point.x).to_bytes(32, "big")

    # HKDF: derive a 256-bit AES key from the shared secret
    aes_key = HKDF(shared_x, AES_KEY_SIZE, salt, SHA256, context=b"ecc-image-enc")

    # AES-256-EAX encryption
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=get_random_bytes(NONCE_SIZE))

    t_enc_start = time.perf_counter()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    t_enc_end = time.perf_counter()

    # Serialize ephemeral public key (raw X ‖ Y, 64 bytes)
    eph_pub_bytes = (
        int(eph_key.pointQ.x).to_bytes(32, "big")
        + int(eph_key.pointQ.y).to_bytes(32, "big")
    )

    # Build output blob: SALT | EPH_PUB | NONCE | TAG | CIPHERTEXT
    output_data = salt + eph_pub_bytes + cipher.nonce + tag + ciphertext

    # Safe write: write to a temp file first, then atomically replace
    dir_name = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        with os.fdopen(fd, "wb") as tmp_f:
            tmp_f.write(output_data)

        # Replace the original only after successful write
        shutil.move(tmp_path, path)
    except Exception:
        # Clean up the temp file if something went wrong
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    t_total_end = time.perf_counter()

    # --- Resource usage ---
    cpu_times_end = process.cpu_times()
    mem_after = process.memory_info().rss
    _, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    cpu_user = cpu_times_end.user - cpu_times_start.user
    cpu_system = cpu_times_end.system - cpu_times_start.system
    cpu_total = cpu_user + cpu_system
    wall_time = t_total_end - t_total_start
    cpu_percent = (cpu_total / wall_time * 100) if wall_time > 0 else 0.0

    mem_used_mb = mem_after / (1024 * 1024)
    mem_peak_mb = mem_peak / (1024 * 1024)

    # --- Performance metrics ---
    kdf_time = t_kdf_end - t_kdf_start
    enc_time = t_enc_end - t_enc_start
    total_time = t_total_end - t_total_start
    size_mb = file_size / (1024 * 1024)
    throughput = size_mb / enc_time if enc_time > 0 else float("inf")

    print(f"[+] Encryption successful: {path}")
    print(f"    Salt       : {salt.hex()}")
    print(f"    Eph. Pub X : {eph_pub_bytes[:32].hex()}")
    print(f"    Eph. Pub Y : {eph_pub_bytes[32:].hex()}")
    print(f"    Nonce      : {cipher.nonce.hex()}")
    print(f"    Tag        : {tag.hex()}")
    print()
    print(f"    --- Performance ---")
    print(f"    File size          : {file_size:,} bytes ({size_mb:.2f} MB)")
    print(f"    Key derivation     : {kdf_time:.4f} s")
    print(f"    Encryption         : {enc_time:.4f} s")
    print(f"    Total time         : {total_time:.4f} s")
    print(f"    Encryption speed   : {throughput:.2f} MB/s")
    print()
    print(f"    --- Resource Usage ---")
    print(f"    CPU usage          : {cpu_percent:.1f}%")
    print(f"    CPU time (user)    : {cpu_user:.4f} s")
    print(f"    CPU time (system)  : {cpu_system:.4f} s")
    print(f"    Memory (current)   : {mem_used_mb:.2f} MB")
    print(f"    Memory (peak alloc): {mem_peak_mb:.2f} MB")
    return path


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------
def decrypt(password: str, path: str) -> str:
    """
    Decrypt a previously encrypted image file in-place.

    Workflow:
      1. Parse SALT, ephemeral public key, NONCE, TAG, CIPHERTEXT.
      2. Re-derive the ECC key pair from the password (PBKDF2).
      3. ECDH with the stored ephemeral public key → same shared secret.
      4. HKDF → same AES key → AES-EAX decrypt & verify tag.

    Parameters:
        password : str – The passphrase used during encryption.
        path     : str – Path to the encrypted file.

    Returns:
        str – The path to the decrypted file (same as *path*).

    Raises:
        ValueError – If the authentication tag verification fails
                     (wrong password or corrupted/tampered file).
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Encrypted file not found: {path}")

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    tracemalloc.start()
    cpu_times_start = process.cpu_times()
    t_total_start = time.perf_counter()

    with open(path, "rb") as f:
        data = f.read()

    # Parse the header
    if len(data) < HEADER_SIZE:
        raise ValueError("File is too small to be a valid encrypted file.")

    offset = 0
    salt = data[offset : offset + SALT_SIZE];                offset += SALT_SIZE
    eph_pub_bytes = data[offset : offset + EPH_PUB_SIZE];    offset += EPH_PUB_SIZE
    nonce = data[offset : offset + NONCE_SIZE];              offset += NONCE_SIZE
    tag = data[offset : offset + TAG_SIZE];                  offset += TAG_SIZE
    ciphertext = data[offset:]

    file_size = len(ciphertext)

    # --- Key derivation (PBKDF2 → ECC key) ---
    t_kdf_start = time.perf_counter()
    password_key = derive_ecc_key(password, salt)
    t_kdf_end = time.perf_counter()

    # Reconstruct ephemeral public key from raw coordinates
    eph_x = int.from_bytes(eph_pub_bytes[:32], "big")
    eph_y = int.from_bytes(eph_pub_bytes[32:], "big")
    eph_pub = ECC.construct(curve="P-256", point_x=eph_x, point_y=eph_y)

    # ECDH: shared_point = eph_pub * password_priv  (same shared secret)
    shared_point = eph_pub.pointQ * int(password_key.d)
    shared_x = int(shared_point.x).to_bytes(32, "big")

    # HKDF: derive the same 256-bit AES key
    aes_key = HKDF(shared_x, AES_KEY_SIZE, salt, SHA256, context=b"ecc-image-enc")

    # AES-256-EAX decryption
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

    t_dec_start = time.perf_counter()
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Authentication failed! The password is incorrect or the "
            "file has been tampered with. The encrypted file is unchanged."
        )
    t_dec_end = time.perf_counter()

    # Safe write: write to a temp file first, then replace
    dir_name = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        with os.fdopen(fd, "wb") as tmp_f:
            tmp_f.write(plaintext)

        shutil.move(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    t_total_end = time.perf_counter()

    # --- Resource usage ---
    cpu_times_end = process.cpu_times()
    mem_after = process.memory_info().rss
    _, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    cpu_user = cpu_times_end.user - cpu_times_start.user
    cpu_system = cpu_times_end.system - cpu_times_start.system
    cpu_total = cpu_user + cpu_system
    wall_time = t_total_end - t_total_start
    cpu_percent = (cpu_total / wall_time * 100) if wall_time > 0 else 0.0

    mem_used_mb = mem_after / (1024 * 1024)
    mem_peak_mb = mem_peak / (1024 * 1024)

    # --- Performance metrics ---
    kdf_time = t_kdf_end - t_kdf_start
    dec_time = t_dec_end - t_dec_start
    total_time = t_total_end - t_total_start
    size_mb = file_size / (1024 * 1024)
    throughput = size_mb / dec_time if dec_time > 0 else float("inf")

    print(f"[+] Decryption successful: {path}")
    print()
    print(f"    --- Performance ---")
    print(f"    File size          : {file_size:,} bytes ({size_mb:.2f} MB)")
    print(f"    Key derivation     : {kdf_time:.4f} s")
    print(f"    Decryption         : {dec_time:.4f} s")
    print(f"    Total time         : {total_time:.4f} s")
    print(f"    Decryption speed   : {throughput:.2f} MB/s")
    print()
    print(f"    --- Resource Usage ---")
    print(f"    CPU usage          : {cpu_percent:.1f}%")
    print(f"    CPU time (user)    : {cpu_user:.4f} s")
    print(f"    CPU time (system)  : {cpu_system:.4f} s")
    print(f"    Memory (current)   : {mem_used_mb:.2f} MB")
    print(f"    Memory (peak alloc): {mem_peak_mb:.2f} MB")
    return path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    """Simple command-line interface for encrypting/decrypting images."""
    print("=" * 60)
    print("  IMAGE SECURITY SYSTEM – ECC / ECIES (P-256 + AES-256-EAX)")
    print("=" * 60)
    print()
    print("  1. Encrypt an image")
    print("  2. Decrypt an image")
    print("  3. Display an image")
    print("  4. Exit")
    print()

    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice == "1":
        path = input("Enter the path to the image file: ").strip()
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match. Aborting.")
            return
        encrypt(password, path)
        print("[*] You can verify the image is now unreadable by opening it.")

    elif choice == "2":
        path = input("Enter the path to the encrypted file: ").strip()
        password = getpass.getpass("Enter decryption password: ")
        try:
            decrypt(password, path)
        except ValueError as e:
            print(f"[!] {e}")

    elif choice == "3":
        path = input("Enter the path to the image file: ").strip()
        imgdis(path)

    elif choice == "4":
        print("Goodbye!")
        sys.exit(0)

    else:
        print("[!] Invalid choice.")


if __name__ == "__main__":
    main()
