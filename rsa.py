"""
rsa.py — Secure Image Encryption using RSA Hybrid Encryption (AES-256-EAX + RSA-2048-OAEP)
Dependencies: pip install pycryptodome psutil
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

import os, sys, stat, struct, shutil, tempfile, time, tracemalloc, getpass
from dataclasses import dataclass
import psutil


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RSA_KEY_BITS        = 2048
AES_KEY_SIZE        = 32
SALT_SIZE           = 32
NONCE_SIZE          = 16
TAG_SIZE            = 16
RSA_BLOCK_SIZE      = RSA_KEY_BITS // 8
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

_ALLOWED_RSA_KEY_BITS  = frozenset({2048, 3072})
_KEY_SIZE_HEADER_FMT   = ">H"
_KEY_SIZE_HEADER_LEN   = struct.calcsize(_KEY_SIZE_HEADER_FMT)
ENC_EXTENSION          = ".enc"
PRIVATE_KEY_FILENAME   = "private_key.pem"
PUBLIC_KEY_FILENAME    = "public_key.pem"


# ---------------------------------------------------------------------------
# RSA Key Management
# ---------------------------------------------------------------------------
def generate_rsa_keypair(export_dir=".", key_bits=RSA_KEY_BITS):
    if key_bits not in _ALLOWED_RSA_KEY_BITS:
        raise ValueError(f"Unsupported RSA key size: {key_bits}. Choose from {sorted(_ALLOWED_RSA_KEY_BITS)}.")

    export_dir = os.path.abspath(export_dir)
    priv_path  = os.path.join(export_dir, PRIVATE_KEY_FILENAME)
    pub_path   = os.path.join(export_dir, PUBLIC_KEY_FILENAME)

    if os.path.isfile(priv_path) and os.path.isfile(pub_path):
        return priv_path, pub_path

    os.makedirs(export_dir, exist_ok=True)
    private_key = RSA.generate(key_bits)
    public_key  = private_key.publickey()

    _write_secure_file(priv_path, private_key.export_key(format="PEM", pkcs=8, protection=None), mode=0o600)
    _write_secure_file(pub_path,  public_key.export_key(format="PEM"), mode=0o644)
    return priv_path, pub_path


def load_public_key(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Public key not found: '{path}'")
    key = RSA.import_key(open(path, "rb").read())
    if key.has_private():
        raise ValueError("Expected a public key file, got a private key.")
    if key.size_in_bits() not in _ALLOWED_RSA_KEY_BITS:
        raise ValueError(f"Unsupported key size: {key.size_in_bits()} bits.")
    return key


def load_private_key(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Private key not found: '{path}'")
    if hasattr(os, "stat"):
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            print(f"[!] WARNING: Private key '{path}' has permissive mode {oct(mode)}. Recommended: chmod 600.")
    key = RSA.import_key(open(path, "rb").read())
    if not key.has_private():
        raise ValueError("Expected a private key file, got a public key.")
    if key.size_in_bits() not in _ALLOWED_RSA_KEY_BITS:
        raise ValueError(f"Unsupported key size: {key.size_in_bits()} bits.")
    return key


def make_oaep_cipher(key):
    return PKCS1_OAEP.new(key, hashAlgo=SHA256)


# ---------------------------------------------------------------------------
# AES-256-EAX Layer
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AesPacket:
    key:        bytes
    nonce:      bytes
    ciphertext: bytes
    tag:        bytes

    def __post_init__(self):
        assert len(self.key)   == AES_KEY_SIZE, f"Bad AES key length: {len(self.key)}"
        assert len(self.nonce) == NONCE_SIZE,   f"Bad nonce length: {len(self.nonce)}"
        assert len(self.tag)   == TAG_SIZE,     f"Bad tag length: {len(self.tag)}"


def _aes_encrypt(plaintext):
    key   = get_random_bytes(AES_KEY_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=TAG_SIZE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return AesPacket(key=key, nonce=nonce, ciphertext=ciphertext, tag=tag)


def _aes_decrypt(packet):
    cipher = AES.new(packet.key, AES.MODE_EAX, nonce=packet.nonce, mac_len=TAG_SIZE)
    plaintext = cipher.decrypt(packet.ciphertext)
    try:
        cipher.verify(packet.tag)
    except ValueError:
        del plaintext
        raise ValueError("AES-EAX authentication FAILED — data may be tampered.")
    return plaintext


# ---------------------------------------------------------------------------
# Decryption Helpers
# ---------------------------------------------------------------------------
def _extract_fields(raw, src_path):
    hdr = _KEY_SIZE_HEADER_LEN
    if len(raw) < hdr:
        raise ValueError(f"'{src_path}': file too short for header.")
    (key_size,) = struct.unpack(_KEY_SIZE_HEADER_FMT, raw[:hdr])

    allowed_bytes = {b // 8 for b in _ALLOWED_RSA_KEY_BITS}
    if key_size not in allowed_bytes:
        raise ValueError(f"'{src_path}': invalid KEY_SIZE={key_size}.")

    offset = hdr
    for name, size in [("RSA key", key_size), ("nonce", NONCE_SIZE), ("tag", TAG_SIZE)]:
        if len(raw) < offset + size:
            raise ValueError(f"'{src_path}': truncated before {name} field.")
        offset += size

    offset = hdr
    enc_key   = raw[offset : offset + key_size];  offset += key_size
    nonce     = raw[offset : offset + NONCE_SIZE]; offset += NONCE_SIZE
    tag       = raw[offset : offset + TAG_SIZE];   offset += TAG_SIZE
    ciphertext = raw[offset:]

    if not ciphertext:
        raise ValueError(f"'{src_path}': no ciphertext found.")
    return enc_key, nonce, tag, ciphertext


def _rsa_decrypt_aes_key(private_key, encrypted_aes_key):
    try:
        aes_key = make_oaep_cipher(private_key).decrypt(encrypted_aes_key)
    except (ValueError, TypeError) as e:
        raise ValueError("RSA-OAEP key unwrap failed — wrong key or corrupted file.") from e
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(f"Decrypted AES key is {len(aes_key)} bytes; expected {AES_KEY_SIZE}.")
    return aes_key


def _verify_and_decrypt_aes(aes_key, nonce, tag, ciphertext, src_path):
    cipher    = AES.new(aes_key, AES.MODE_EAX, nonce=nonce, mac_len=TAG_SIZE)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
    except ValueError:
        del plaintext
        raise ValueError(
            f"Authentication tag FAILED for '{src_path}'.\n"
            "  • Ciphertext/tag/nonce was tampered with, or wrong key was used."
        )
    return plaintext


# ---------------------------------------------------------------------------
# File I/O Helpers
# ---------------------------------------------------------------------------
def _write_secure_file(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _safe_write_file(dest_path, data):
    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".tmp", dir=dest_dir)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        shutil.move(tmp_path, dest_path)
        tmp_path = None
    except Exception:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


# ---------------------------------------------------------------------------
# Core: encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt(password, path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Image not found: '{path}'")

    pub_key_path = os.path.join(os.path.dirname(path), PUBLIC_KEY_FILENAME)
    public_key   = load_public_key(pub_key_path)

    # Performance probes
    process = psutil.Process(os.getpid())
    tracemalloc.start()
    cpu_start   = process.cpu_times()
    t_start     = time.perf_counter()

    plaintext = open(path, "rb").read()
    file_size = len(plaintext)

    t_aes_s = time.perf_counter()
    packet  = _aes_encrypt(plaintext)
    t_aes_e = time.perf_counter()

    t_rsa_s     = time.perf_counter()
    enc_aes_key = make_oaep_cipher(public_key).encrypt(packet.key)
    t_rsa_e     = time.perf_counter()

    key_size   = len(enc_aes_key)
    payload    = (
        struct.pack(_KEY_SIZE_HEADER_FMT, key_size)
        + enc_aes_key
        + packet.nonce
        + packet.tag
        + packet.ciphertext
    )

    out_path = path + ENC_EXTENSION
    _safe_write_file(out_path, payload)

    t_end     = time.perf_counter()
    cpu_end   = process.cpu_times()
    _, mem_pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    _print_metrics("Encryption", file_size, t_aes_e - t_aes_s, t_rsa_e - t_rsa_s,
                   t_end - t_start, cpu_start, cpu_end, process.memory_info().rss, mem_pk)
    print(f"    Nonce : {packet.nonce.hex()}")
    print(f"    Tag   : {packet.tag.hex()}")
    return out_path


def decrypt(password, path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Encrypted file not found: '{path}'")

    priv_key_path = os.path.join(os.path.dirname(path), PRIVATE_KEY_FILENAME)
    private_key   = load_private_key(priv_key_path)

    # Performance probes
    process = psutil.Process(os.getpid())
    tracemalloc.start()
    cpu_start = process.cpu_times()
    t_start   = time.perf_counter()

    raw                             = open(path, "rb").read()
    enc_aes_key, nonce, tag, ctxt  = _extract_fields(raw, path)
    file_size                       = len(ctxt)

    t_rsa_s = time.perf_counter()
    aes_key = _rsa_decrypt_aes_key(private_key, enc_aes_key)
    t_rsa_e = time.perf_counter()

    t_aes_s   = time.perf_counter()
    plaintext = _verify_and_decrypt_aes(aes_key, nonce, tag, ctxt, path)
    t_aes_e   = time.perf_counter()

    out_path = path[: -len(ENC_EXTENSION)] if path.endswith(ENC_EXTENSION) else path + ".dec"
    _safe_write_file(out_path, plaintext)

    t_end     = time.perf_counter()
    cpu_end   = process.cpu_times()
    _, mem_pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    _print_metrics("Decryption", file_size, t_aes_e - t_aes_s, t_rsa_e - t_rsa_s,
                   t_end - t_start, cpu_start, cpu_end, process.memory_info().rss, mem_pk)
    return out_path


# ---------------------------------------------------------------------------
# Metrics printer
# ---------------------------------------------------------------------------
def _print_metrics(label, file_size, aes_time, rsa_time, total_time,
                   cpu_start, cpu_end, mem_rss, mem_peak):
    size_mb    = file_size / (1024 * 1024)
    throughput = size_mb / aes_time if aes_time > 0 else float("inf")
    cpu_user   = cpu_end.user   - cpu_start.user
    cpu_sys    = cpu_end.system - cpu_start.system
    cpu_pct    = ((cpu_user + cpu_sys) / total_time * 100) if total_time > 0 else 0.0

    rsa_label = "RSA-OAEP key wrap  " if label == "Encryption" else "RSA-OAEP key unwrap"
    aes_label = "AES-256-EAX enc    " if label == "Encryption" else "AES-256-EAX dec    "
    speed_lbl = "Encryption speed   " if label == "Encryption" else "Decryption speed   "

    print(f"\n[+] {label} successful")
    print(f"    --- Performance ---")
    print(f"    File size          : {file_size:,} bytes ({size_mb:.2f} MB)")
    print(f"    {rsa_label}: {rsa_time:.4f} s")
    print(f"    {aes_label}: {aes_time:.4f} s")
    print(f"    Total time         : {total_time:.4f} s")
    print(f"    {speed_lbl}: {throughput:.2f} MB/s")
    print(f"    --- Resource Usage ---")
    print(f"    CPU usage          : {cpu_pct:.1f}%")
    print(f"    CPU time (user)    : {cpu_user:.4f} s")
    print(f"    CPU time (system)  : {cpu_sys:.4f} s")
    print(f"    Memory (current)   : {mem_rss / (1024*1024):.2f} MB")
    print(f"    Memory (peak alloc): {mem_peak / (1024*1024):.2f} MB")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("  IMAGE SECURITY SYSTEM – RSA-2048 + AES-256-EAX (Hybrid)")
    print("=" * 60)
    print("\n  1. Generate RSA key pair")
    print("  2. Encrypt an image")
    print("  3. Decrypt an image")
    print("  4. Exit\n")

    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice == "1":
        export_dir = input("Key directory (blank = current): ").strip() or "."
        bits_in    = input(f"Key size [2048/3072] (blank = {RSA_KEY_BITS}): ").strip()
        key_bits   = int(bits_in) if bits_in else RSA_KEY_BITS
        try:
            priv, pub = generate_rsa_keypair(export_dir=export_dir, key_bits=key_bits)
            print(f"[+] Key pair generated.\n    Private: {priv}\n    Public : {pub}")
        except ValueError as e:
            print(f"[!] {e}")

    elif choice == "2":
        path     = input("Image file path: ").strip()
        password = getpass.getpass("Password (press Enter to skip): ")
        try:
            out = encrypt(password, path)
            print(f"[*] Encrypted → {out}")
        except (FileNotFoundError, ValueError, OSError) as e:
            print(f"[!] Encryption failed: {e}")

    elif choice == "3":
        path     = input("Encrypted (.enc) file path: ").strip()
        password = getpass.getpass("Password (press Enter to skip): ")
        try:
            out = decrypt(password, path)
            print(f"[*] Restored → {out}")
        except (FileNotFoundError, ValueError, OSError) as e:
            print(f"[!] Decryption failed: {e}")

    elif choice == "4":
        print("Goodbye!")
        sys.exit(0)

    else:
        print("[!] Invalid choice.")


if __name__ == "__main__":
    main()
