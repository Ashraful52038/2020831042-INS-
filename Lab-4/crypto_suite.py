#!/usr/bin/env python3
import os, sys, argparse, json, time, csv, math, secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hmac
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
KEYS = BASE / "keys"
DATA = BASE / "data"
RES  = BASE / "results"
for p in (KEYS, DATA, RES): p.mkdir(exist_ok=True, parents=True)

def write_bytes(path: Path, b: bytes):
    path.parent.mkdir(exist_ok=True, parents=True)
    with open(path, "wb") as f: f.write(b)

def read_bytes(path: Path) -> bytes:
    with open(path, "rb") as f: return f.read()

def now_ms(): return int(time.perf_counter() * 1000)

def pad_pkcs7(data: bytes, block=16):
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs7(padded: bytes):
    if not padded: return padded
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16: raise ValueError("bad padding")
    if padded[-pad_len:] != bytes([pad_len])*pad_len: raise ValueError("bad padding")
    return padded[:-pad_len]

def derive_aes_key(desired_bits: int):
    if desired_bits <= 128: key_len = 16
    elif desired_bits <= 192: key_len = 24
    else: key_len = 32
    bytes_needed = math.ceil(desired_bits/8)
    raw = secrets.token_bytes(max(1, min(bytes_needed, key_len)))
    key = raw.ljust(key_len, b"\x00")
    return key

def aes_encrypt_file(infile: Path, outfile: Path, mode: str, key_bits: int, iv_file: Path=None):
    pt = read_bytes(infile)
    key = derive_aes_key(key_bits)
    if mode.upper() == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(pad_pkcs7(pt)) + enc.finalize()
        write_bytes(outfile, ct)
        return len(pt)
    elif mode.upper() == "CFB":
        iv = read_bytes(iv_file) if (iv_file and iv_file.exists()) else secrets.token_bytes(16)
        if iv_file and not iv_file.exists(): write_bytes(iv_file, iv)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(pt) + enc.finalize()
        write_bytes(outfile, iv + ct)  # prepend IV
        return len(pt)
    else:
        raise ValueError("mode must be ECB or CFB")

def aes_decrypt_file(infile: Path, outfile: Path, mode: str, key_bits: int):
    key = derive_aes_key(key_bits)
    data = read_bytes(infile)
    if mode.upper() == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        pt = unpad_pkcs7(dec.update(data) + dec.finalize())
        write_bytes(outfile, pt)
        return len(pt)
    elif mode.upper() == "CFB":
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()
        write_bytes(outfile, pt)
        return len(pt)
    else:
        raise ValueError("mode must be ECB or CFB")

def rsa_generate(bits: int, priv_path: Path, pub_path: Path):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pem_priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pem_pub  = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    write_bytes(priv_path, pem_priv); write_bytes(pub_path, pem_pub)

def rsa_encrypt(infile: Path, outfile: Path, pub_path: Path):
    pub = serialization.load_pem_public_key(read_bytes(pub_path), backend=default_backend())
    data = read_bytes(infile)
    ct = pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
    write_bytes(outfile, ct)

def rsa_decrypt(infile: Path, outfile: Path, priv_path: Path):
    priv = serialization.load_pem_private_key(read_bytes(priv_path), password=None, backend=default_backend())
    ct = read_bytes(infile)
    pt = priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    write_bytes(outfile, pt)

def rsa_sign(infile: Path, sig_path: Path, priv_path: Path):
    priv = serialization.load_pem_private_key(read_bytes(priv_path), password=None, backend=default_backend())
    data = read_bytes(infile)
    sig = priv.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    write_bytes(sig_path, sig)

def rsa_verify(infile: Path, sig_path: Path, pub_path: Path) -> bool:
    pub = serialization.load_pem_public_key(read_bytes(pub_path), backend=default_backend())
    data = read_bytes(infile); sig = read_bytes(sig_path)
    try:
        pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False

def sha256_file(infile: Path):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(infile, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): digest.update(chunk)
    return digest.finalize().hex()

def measure_aes_timings(infile: Path, modes=("ECB","CFB"), Ns=(16,32,64,128,256)):
    rows=[]
    for mode in modes:
        for n in Ns:
            t0 = now_ms()
            out = RES / f"aes_{mode}_{n}.bin"
            ivf = KEYS / f"iv_{mode}_{n}.bin"
            aes_encrypt_file(infile, out, mode, n, ivf)
            enc_ms = now_ms()-t0
            t1 = now_ms()
            dec = RES / f"aes_{mode}_{n}.dec"
            aes_decrypt_file(out, dec, mode, n)
            dec_ms = now_ms()-t1
            rows.append({"algo": f"AES-{mode}", "key_bits": n, "enc_ms": enc_ms, "dec_ms": dec_ms})
    csv_path = RES / "aes_timings.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["algo","key_bits","enc_ms","dec_ms"]); w.writeheader(); w.writerows(rows)
    for mode in modes:
        xs = [r["key_bits"] for r in rows if r["algo"]==f"AES-{mode}"]
        ys = [r["enc_ms"]  for r in rows if r["algo"]==f"AES-{mode}"]
        plt.plot(xs, ys, marker="o", label=f"{mode} enc")
    plt.xlabel("Key bits (requested)"); plt.ylabel("Time (ms)"); plt.title("AES timings")
    plt.legend(); plt.grid(True); plt.tight_layout(); plt.savefig(RES / "aes_timings.png"); plt.clf()
    return csv_path

def measure_rsa_timings(infile: Path, Ns=(512,1024,1536,2048,3072)):
    rows=[]
    for n in Ns:
        priv = KEYS / f"rsa_{n}_priv.pem"; pub  = KEYS / f"rsa_{n}_pub.pem"
        t0 = now_ms(); rsa_generate(n, priv, pub); keygen_ms = now_ms()-t0
        ct = RES / f"rsa_{n}.bin"
        t1 = now_ms(); rsa_encrypt(infile, ct, pub);  enc_ms = now_ms()-t1
        out = RES / f"rsa_{n}.dec"
        t2 = now_ms(); rsa_decrypt(ct, out, priv);     dec_ms = now_ms()-t2
        rows.append({"algo":"RSA", "key_bits": n, "keygen_ms": keygen_ms, "enc_ms": enc_ms, "dec_ms": dec_ms})
    csv_path = RES / "rsa_timings.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["algo","key_bits","keygen_ms","enc_ms","dec_ms"])
        w.writeheader(); w.writerows(rows)
    xs = [r["key_bits"] for r in rows]
    plt.plot(xs, [r["keygen_ms"] for r in rows], marker="o", label="keygen")
    plt.plot(xs, [r["enc_ms"] for r in rows],   marker="o", label="encrypt")
    plt.plot(xs, [r["dec_ms"] for r in rows],   marker="o", label="decrypt")
    plt.xlabel("RSA key bits"); plt.ylabel("Time (ms)"); plt.title("RSA timings")
    plt.legend(); plt.grid(True); plt.tight_layout(); plt.savefig(RES / "rsa_timings.png"); plt.clf()
    return csv_path

def main():
    ap = argparse.ArgumentParser(description="Lab 4 Crypto Suite")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("menu", help="Interactive menu")
    p_gen = sub.add_parser("genkeys", help="Generate AES and RSA keys"); p_gen.add_argument("--rsa-bits", type=int, default=2048)
    p_aes_e = sub.add_parser("aes-enc", help="AES encrypt file")
    p_aes_e.add_argument("--in", dest="inf", required=True); p_aes_e.add_argument("--out", dest="outf", required=True)
    p_aes_e.add_argument("--mode", choices=["ECB","CFB"], required=True); p_aes_e.add_argument("--key-bits", type=int, choices=[128,256], required=True)
    p_aes_d = sub.add_parser("aes-dec", help="AES decrypt file")
    p_aes_d.add_argument("--in", dest="inf", required=True); p_aes_d.add_argument("--out", dest="outf", required=True)
    p_aes_d.add_argument("--mode", choices=["ECB","CFB"], required=True); p_aes_d.add_argument("--key-bits", type=int, choices=[128,256], required=True)
    p_renc = sub.add_parser("rsa-enc", help="RSA encrypt (OAEP)"); p_renc.add_argument("--in", dest="inf", required=True); p_renc.add_argument("--out", dest="outf", required=True)
    p_rdec = sub.add_parser("rsa-dec", help="RSA decrypt (OAEP)"); p_rdec.add_argument("--in", dest="inf", required=True); p_rdec.add_argument("--out", dest="outf", required=True)
    p_sign = sub.add_parser("rsa-sign", help="RSA sign (PSS)");    p_sign.add_argument("--in", dest="inf", required=True); p_sign.add_argument("--sig", dest="sig", required=True)
    p_vfy  = sub.add_parser("rsa-verify", help="RSA verify (PSS)");p_vfy.add_argument("--in", dest="inf", required=True); p_vfy.add_argument("--sig", dest="sig", required=True)
    p_sha  = sub.add_parser("sha256", help="SHA-256 of a file");   p_sha.add_argument("--in", dest="inf", required=True)
    p_meas = sub.add_parser("measure", help="Run timing experiments & plots"); p_meas.add_argument("--in", dest="inf", required=True)
    args = ap.parse_args()

    aes128 = KEYS / "aes_128.key"; aes256 = KEYS / "aes_256.key"
    rsa_priv = KEYS / "rsa_priv.pem"; rsa_pub  = KEYS / "rsa_pub.pem"

    if args.cmd == "genkeys":
        write_bytes(aes128, secrets.token_bytes(16))
        write_bytes(aes256, secrets.token_bytes(32))
        rsa_generate(args.rsa_bits, rsa_priv, rsa_pub)
        print(f"Generated: {aes128}, {aes256}, {rsa_priv}, {rsa_pub}")

    elif args.cmd == "aes-enc":
        src = Path(args.inf); dst = Path(args.outf); t0 = now_ms()
        ivf = KEYS / f"iv_{args.mode}_{args.key_bits}.bin"
        aes_encrypt_file(src, dst, args.mode, args.key_bits, ivf)
        print(f"[AES-{args.mode}] Encrypt done in {now_ms()-t0} ms -> {dst}")

    elif args.cmd == "aes-dec":
        src = Path(args.inf); dst = Path(args.outf); t0 = now_ms()
        aes_decrypt_file(src, dst, args.mode, args.key_bits)
        print(f"[AES-{args.mode}] Decrypt done in {now_ms()-t0} ms -> {dst}")
        print(dst.read_bytes()[:200])

    elif args.cmd == "rsa-enc":
        src = Path(args.inf); dst = Path(args.outf)
        if not rsa_pub.exists():
            print("No RSA keys. Run: python3 crypto_suite.py genkeys"); sys.exit(1)
        t0 = now_ms(); rsa_encrypt(src, dst, rsa_pub); print(f"[RSA] Encrypt done in {now_ms()-t0} ms -> {dst}")

    elif args.cmd == "rsa-dec":
        src = Path(args.inf); dst = Path(args.outf)
        if not rsa_priv.exists():
            print("No RSA keys. Run: python3 crypto_suite.py genkeys"); sys.exit(1)
        t0 = now_ms(); rsa_decrypt(src, dst, rsa_priv); print(f"[RSA] Decrypt done in {now_ms()-t0} ms -> {dst}")
        print(dst.read_bytes()[:200])

    elif args.cmd == "rsa-sign":
        src = Path(args.inf); sig = Path(args.sig)
        if not rsa_priv.exists():
            print("No RSA keys. Run: python3 crypto_suite.py genkeys"); sys.exit(1)
        t0 = now_ms(); rsa_sign(src, sig, rsa_priv); print(f"[RSA] Signature written to {sig} in {now_ms()-t0} ms")

    elif args.cmd == "rsa-verify":
        src = Path(args.inf); sig = Path(args.sig)
        if not rsa_pub.exists():
            print("No RSA keys. Run: python3 crypto_suite.py genkeys"); sys.exit(1)
        t0 = now_ms(); ok = rsa_verify(src, sig, rsa_pub); print(f"[RSA] Verify: {'OK' if ok else 'FAIL'} in {now_ms()-t0} ms")

    elif args.cmd == "sha256":
        h = sha256_file(Path(args.inf)); print(f"SHA-256({args.inf}) = {h}")

    elif args.cmd == "measure":
        src = Path(args.inf)
        print("Measuring AES timings..."); aes_csv = measure_aes_timings(src); print(f"Wrote {aes_csv} and results/aes_timings.png")
        print("Measuring RSA timings..."); rsa_csv = measure_rsa_timings(src); print(f"Wrote {rsa_csv} and results/rsa_timings.png")
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
PY
