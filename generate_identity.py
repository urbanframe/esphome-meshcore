#!/usr/bin/env python3
"""Generate an Ed25519 keypair in the exact format MeshCore uses, so you can
pin a stable node identity in secrets.yaml instead of letting the component
generate (and lose, on every reboot) an ephemeral one.

MeshCore's private_key on the wire/in its own config is the 64-byte
libsodium/ed25519-donna "expanded" secret key (32-byte seed-derived scalar +
32-byte prefix), matching the vendored orlp/ed25519 library this component
also uses (ed25519_create_keypair). We reuse the *same* C library via a tiny
cffi-free ctypes shim compiled on the fly, so the output is guaranteed to
match what the ESP32-side code will produce from the same seed — no separate
crypto implementation to accidentally get subtly wrong.

Usage:
    python3 generate_identity.py

Requires a C compiler (cc/gcc/clang) on PATH.
"""
import ctypes
import os
import secrets
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ED25519_DIR = os.path.join(HERE, "..", "components", "meshcore", "ed25519")


def build_shared_lib(tmpdir: str) -> str:
    sources = [
        f
        for f in os.listdir(ED25519_DIR)
        if f.endswith(".c")
    ]
    out = os.path.join(tmpdir, "libed25519.so" if sys.platform != "darwin" else "libed25519.dylib")
    cmd = ["cc", "-shared", "-fPIC", "-O2", "-DED25519_NO_SEED", "-o", out] + [
        os.path.join(ED25519_DIR, f) for f in sources
    ]
    subprocess.run(cmd, check=True)
    return out


def main():
    seed = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory() as tmp:
        lib_path = build_shared_lib(tmp)
        lib = ctypes.CDLL(lib_path)
        pub = ctypes.create_string_buffer(32)
        prv = ctypes.create_string_buffer(64)
        lib.ed25519_create_keypair(pub, prv, seed)

        pub_hex = pub.raw.hex()
        prv_hex = prv.raw.hex()

    print("Add these to secrets.yaml:\n")
    print(f"meshcore_public_key: \"{pub_hex}\"")
    print(f"meshcore_private_key: \"{prv_hex}\"")
    print("\nThis is your node's permanent identity on the mesh — back it up.")


if __name__ == "__main__":
    main()
