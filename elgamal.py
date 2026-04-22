"""
elgamal.py — Secure Image Encryption: ElGamal + AES-256-EAX (Hybrid)
Dependencies: pip install pycryptodome psutil
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

import os, sys, struct, shutil, tempfile, time, tracemalloc, getpass
from dataclasses import dataclass
import psutil


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_SIZE  = 32
NONCE_SIZE    = 16
TAG_SIZE      = 16
PRIME_BITS    = 2048
ENC_EXTENSION = ".enc"
KEY_FILENAME  = "elgamal_key.bin"
_HDR_FMT      = ">H"
_HDR_LEN      = struct.calcsize(_HDR_FMT)


# ---------------------------------------------------------------------------
# Key structures
# ---------------------------------------------------------------------------
@dataclass
class ElGamalPublicKey:
    p: int; g: int; h: int

@dataclass
class ElGamalPrivateKey:
    p: int; g: int; x: int


# ---------------------------------------------------------------------------
# Key serialization helpers
# ---------------------------------------------------------------------------
def _int_pack(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return struct.pack(">I", len(b)) + b

def _int_read(data, off, label):
    if off + 4 > len(data):
        raise ValueError(f"Truncated at '{label}' length.")
    (blen,) = struct.unpack_from(">I", data, off); off += 4
    if off + blen > len(data):
        raise ValueError(f"Truncated at '{label}' value.")
    return int.from_bytes(data[off:off + blen], "big"), off + blen


# ---------------------------------------------------------------------------
# Key generation & loading
# ---------------------------------------------------------------------------
def generate_elgamal_keypair(export_path=KEY_FILENAME, prime_bits=PRIME_BITS):
    if prime_bits < 512:
        raise ValueError("prime_bits must be >= 512.")

    p = getPrime(prime_bits)
    g = 2

    byte_len = (prime_bits + 7) // 8
    while True:
        x = (bytes_to_long(get_random_bytes(byte_len)) % (p - 3)) + 2
        if 2 <= x <= p - 2:
            break

    h = pow(g, x, p)
    pub  = ElGamalPublicKey(p=p, g=g, h=h)
    priv = ElGamalPrivateKey(p=p, g=g, x=x)

    blob = _int_pack(p) + _int_pack(g) + _int_pack(x) + _int_pack(h)
    export_path = os.path.abspath(export_path)
    os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
    _safe_write(export_path, blob)   # atomic: temp-file → fsync → shutil.move

    print(f"[+] ElGamal key pair generated ({prime_bits}-bit prime).")
    print(f"    Key file : {export_path}")
    print(f"    p (bits) : {p.bit_length()}  |  g : {g}  |  h (bits) : {h.bit_length()}")
    return pub, priv


def load_elgamal_keys(path=KEY_FILENAME):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Key file not found: '{path}'. Run option 1 first.")
    data = open(path, "rb").read()
    off  = 0
    p, off = _int_read(data, off, "p")
    g, off = _int_read(data, off, "g")
    x, off = _int_read(data, off, "x")
    h, off = _int_read(data, off, "h")
    return ElGamalPublicKey(p=p, g=g, h=h), ElGamalPrivateKey(p=p, g=g, x=x)


# ---------------------------------------------------------------------------
# ElGamal encrypt / decrypt (AES session key only)
# ---------------------------------------------------------------------------
def elgamal_encrypt_key(pub, aes_key):
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(f"aes_key must be {AES_KEY_SIZE} bytes.")
    p, g, h = pub.p, pub.g, pub.h
    m = bytes_to_long(aes_key)
    if m >= p:
        raise ValueError("Key integer m >= p.")

    byte_len = (p.bit_length() + 7) // 8
    while True:
        k = (bytes_to_long(get_random_bytes(byte_len)) % (p - 3)) + 2
        if 2 <= k <= p - 2:
            break

    C1 = pow(g, k, p)
    C2 = (m * pow(h, k, p)) % p
    return C1, C2


def elgamal_decrypt_key(priv, C1, C2):
    p, x  = priv.p, priv.x
    s     = pow(C1, x, p)
    if s == 0:
        raise ValueError("Shared secret s = 0.")
    s_inv = inverse(s, p)
    m     = (C2 * s_inv) % p
    key   = long_to_bytes(m, AES_KEY_SIZE)
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Recovered key is {len(key)}B, expected {AES_KEY_SIZE}B.")
    return key


# ---------------------------------------------------------------------------
# AES-256-EAX encrypt / decrypt
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AesPacket:
    nonce: bytes; ciphertext: bytes; tag: bytes

def _aes_encrypt(aes_key, plaintext):
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce, mac_len=TAG_SIZE)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return AesPacket(nonce=nonce, ciphertext=ct, tag=tag)

def _aes_decrypt(aes_key, packet):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=packet.nonce, mac_len=TAG_SIZE)
    pt = cipher.decrypt(packet.ciphertext)
    try:
        cipher.verify(packet.tag)
    except ValueError:
        del pt
        raise ValueError("AES-EAX authentication FAILED — tampered data or wrong key.")
    return pt


# ---------------------------------------------------------------------------
# Binary pack / unpack: [C1_LEN|C1 | C2_LEN|C2 | NONCE | TAG | CIPHERTEXT]
# ---------------------------------------------------------------------------
def _pack(C1, C2, packet):
    c1b = long_to_bytes(C1)
    c2b = long_to_bytes(C2)
    return (
        struct.pack(_HDR_FMT, len(c1b)) + c1b
        + struct.pack(_HDR_FMT, len(c2b)) + c2b
        + packet.nonce + packet.tag + packet.ciphertext
    )

def _unpack(raw, path):
    off = 0

    def read(n, label):
        nonlocal off
        if off + n > len(raw):
            raise ValueError(f"'{path}': truncated at '{label}' (need {n}B at {off}).")
        chunk = raw[off:off + n]; off += n
        return chunk

    def read_int(label):
        (blen,) = struct.unpack(_HDR_FMT, read(_HDR_LEN, f"{label}_len"))
        if blen == 0:
            raise ValueError(f"'{path}': {label} length is zero.")
        return bytes_to_long(read(blen, label))

    C1    = read_int("C1")
    C2    = read_int("C2")
    nonce = read(NONCE_SIZE, "nonce")
    tag   = read(TAG_SIZE,   "tag")
    ct    = raw[off:]
    if not ct:
        raise ValueError(f"'{path}': no ciphertext found.")
    return C1, C2, AesPacket(nonce=nonce, ciphertext=ct, tag=tag)


# ---------------------------------------------------------------------------
# Safe atomic file write
# ---------------------------------------------------------------------------
def _safe_write(dest, data):
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".tmp", dir=os.path.dirname(os.path.abspath(dest)))
        try:
            # os.write() may do partial writes on Windows — loop until all bytes are written.
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        shutil.move(tmp, dest)   # atomic rename; tmp cleanup no longer needed
        tmp = None
    except Exception:
        if tmp and os.path.exists(tmp):
            try: os.unlink(tmp)
            except OSError: pass
        raise


# ---------------------------------------------------------------------------
# Metrics printer
# ---------------------------------------------------------------------------
def _print_metrics(label, file_size, el_time, aes_time, total_time,
                   cpu_start, cpu_end, mem_rss, mem_peak):
    size_mb    = file_size / (1024 * 1024)
    throughput = size_mb / aes_time if aes_time > 0 else float("inf")
    cpu_user   = cpu_end.user   - cpu_start.user
    cpu_sys    = cpu_end.system - cpu_start.system
    cpu_pct    = ((cpu_user + cpu_sys) / total_time * 100) if total_time > 0 else 0.0
    el_lbl  = "ElGamal key encrypt  " if label == "Encryption" else "ElGamal key decrypt  "
    aes_lbl = "AES-256-EAX enc      " if label == "Encryption" else "AES-256-EAX dec      "
    spd_lbl = "Encryption speed     " if label == "Encryption" else "Decryption speed     "
    print(f"\n[+] {label} successful")
    print(f"    --- Performance ---")
    print(f"    File size            : {file_size:,} bytes ({size_mb:.2f} MB)")
    print(f"    {el_lbl}: {el_time:.4f} s")
    print(f"    {aes_lbl}: {aes_time:.4f} s")
    print(f"    Total time           : {total_time:.4f} s")
    print(f"    {spd_lbl}: {throughput:.2f} MB/s")
    print(f"    --- Resource Usage ---")
    print(f"    CPU usage            : {cpu_pct:.1f}%")
    print(f"    CPU time (user)      : {cpu_user:.4f} s")
    print(f"    CPU time (system)    : {cpu_sys:.4f} s")
    print(f"    Memory (current)     : {mem_rss / (1024*1024):.2f} MB")
    print(f"    Memory (peak alloc)  : {mem_peak / (1024*1024):.2f} MB")


# ---------------------------------------------------------------------------
# Core: encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt(password, path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Image not found: '{path}'")

    pub, _ = load_elgamal_keys(os.path.join(os.path.dirname(path), KEY_FILENAME))

    process = psutil.Process(os.getpid())
    tracemalloc.start()
    cpu_start = process.cpu_times()
    t_start   = time.perf_counter()

    plaintext = open(path, "rb").read()
    aes_key   = get_random_bytes(AES_KEY_SIZE)

    t_aes_s = time.perf_counter()
    packet  = _aes_encrypt(aes_key, plaintext)
    t_aes_e = time.perf_counter()

    t_el_s = time.perf_counter()
    C1, C2 = elgamal_encrypt_key(pub, aes_key)
    t_el_e = time.perf_counter()

    out_path = path + ENC_EXTENSION
    _safe_write(out_path, _pack(C1, C2, packet))

    t_end     = time.perf_counter()
    cpu_end   = process.cpu_times()
    _, mem_pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"    Nonce : {packet.nonce.hex()}")
    print(f"    Tag   : {packet.tag.hex()}")
    _print_metrics("Encryption", len(plaintext),
                   t_el_e - t_el_s, t_aes_e - t_aes_s, t_end - t_start,
                   cpu_start, cpu_end, process.memory_info().rss, mem_pk)
    return out_path


def decrypt(password, path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Encrypted file not found: '{path}'")

    _, priv = load_elgamal_keys(os.path.join(os.path.dirname(path), KEY_FILENAME))

    process = psutil.Process(os.getpid())
    tracemalloc.start()
    cpu_start = process.cpu_times()
    t_start   = time.perf_counter()

    C1, C2, packet = _unpack(open(path, "rb").read(), path)

    t_el_s  = time.perf_counter()
    aes_key = elgamal_decrypt_key(priv, C1, C2)
    t_el_e  = time.perf_counter()

    t_aes_s   = time.perf_counter()
    plaintext = _aes_decrypt(aes_key, packet)
    t_aes_e   = time.perf_counter()

    out_path = path[:-len(ENC_EXTENSION)] if path.endswith(ENC_EXTENSION) else path + ".dec"
    _safe_write(out_path, plaintext)

    t_end     = time.perf_counter()
    cpu_end   = process.cpu_times()
    _, mem_pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    _print_metrics("Decryption", len(packet.ciphertext),
                   t_el_e - t_el_s, t_aes_e - t_aes_s, t_end - t_start,
                   cpu_start, cpu_end, process.memory_info().rss, mem_pk)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("  IMAGE SECURITY SYSTEM – ElGamal + AES-256-EAX (Hybrid)")
    print("=" * 60)
    print("\n  1. Generate ElGamal key pair")
    print("  2. Encrypt an image")
    print("  3. Decrypt an image")
    print("  4. Exit\n")

    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice == "1":
        export = input("Key file path (blank = current dir): ").strip() or KEY_FILENAME
        try:
            generate_elgamal_keypair(export_path=export)
        except (ValueError, OSError) as e:
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
