# -*- coding: utf-8 -*-
"""IMAGE ENCRYPTION & DECRYPTION USING AES

IMAGE SECURITY SYSTEM FOR ARMY, POLICE & SECURE COMMUNICATION

This script provides secure image encryption and decryption using
AES-256 in EAX authenticated encryption mode.

Security features:
  1. PBKDF2 key derivation (replaces insecure MD5 hashing)
  2. Random nonce per encryption with authentication tag verification
  3. Safe file overwriting via temporary files to prevent data loss

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
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SALT_SIZE = 16          # bytes – unique per encryption
NONCE_SIZE = 16         # bytes – AES-EAX uses 128-bit nonces
TAG_SIZE = 16           # bytes – authentication tag length (AES block size)
KDF_ITERATIONS = 600_000  # PBKDF2 iteration count (OWASP recommendation)
KEY_SIZE = 32           # bytes – AES-256 (256-bit)

# File layout: SALT (16) | NONCE (16) | TAG (16) | CIPHERTEXT (rest)


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
# Key derivation – PBKDF2 (replaces insecure MD5)
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte (256-bit) AES key from *password* using PBKDF2-HMAC-SHA256.

    Using a high iteration count makes brute-force attacks computationally
    expensive, unlike a single pass of MD5.

    Parameters:
        password : str   – The user's secret passphrase.
        salt     : bytes – A random salt (must be stored alongside ciphertext).

    Returns:
        bytes – A 32-byte key suitable for AES-256.
    """
    key = PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZE,
        count=KDF_ITERATIONS,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )
    return key


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
def encrypt(password: str, path: str) -> str:
    """
    Encrypt an image file in-place using AES-256 in EAX mode.

    Security properties:
      • A fresh random salt and nonce are generated for every call.
      • An authentication tag (MAC) is produced so tampering is detected
        during decryption.
      • The original file is only replaced **after** the encrypted output
        has been fully written to a temporary file, preventing data loss
        on error.

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

    t_kdf_start = time.perf_counter()
    key = derive_key(password, salt)
    t_kdf_end = time.perf_counter()

    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(NONCE_SIZE))

    # Encrypt and produce the authentication tag
    t_enc_start = time.perf_counter()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    t_enc_end = time.perf_counter()

    # Build the output blob: SALT | NONCE | TAG | CIPHERTEXT
    output_data = salt + cipher.nonce + tag + ciphertext

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
    # CPU usage % = (CPU time used / wall time) * 100, capped at nCPUs * 100
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
    print(f"    Salt   : {salt.hex()}")
    print(f"    Nonce  : {cipher.nonce.hex()}")
    print(f"    Tag    : {tag.hex()}")
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

    The function reads the salt, nonce, and authentication tag stored at the
    beginning of the file, re-derives the key via PBKDF2, and verifies the
    tag before accepting the plaintext.  If the tag does not match (wrong
    password or tampered file), a ``ValueError`` is raised and the encrypted
    file is left untouched.

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
    header_size = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(data) < header_size:
        raise ValueError("File is too small to be a valid encrypted file.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE : header_size]
    ciphertext = data[header_size:]

    file_size = len(ciphertext)

    # Re-derive the same key
    t_kdf_start = time.perf_counter()
    key = derive_key(password, salt)
    t_kdf_end = time.perf_counter()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    # Decrypt and verify the authentication tag
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
    print("  IMAGE SECURITY SYSTEM – AES-256 (EAX Mode)")
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
