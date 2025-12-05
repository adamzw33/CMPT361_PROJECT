import socket
import sys
import os, glob, datetime
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_BLOCK = AES.block_size
FRAME_LEN_BYTES = 8

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        pkt = conn.recv(n - len(data))
        if not pkt:
            return None
        data += pkt
    return data

def send_framed(conn, data_bytes):
    ln = len(data_bytes)
    conn.sendall(ln.to_bytes(FRAME_LEN_BYTES, "big") + data_bytes)

def recv_framed(conn):
    header = recv_all(conn, FRAME_LEN_BYTES)
    if not header:
        return None
    ln = int.from_bytes(header, "big")
    return recv_all(conn, ln)

def load_keys(username):
    keys = {}
    with open(f"{username}_private.pem", "rb") as f:
        keys["client_private"] = RSA.import_key(f.read())
    with open(f"{username}_public.pem", "rb") as f:
        keys["client_public"] = RSA.import_key(f.read())
    with open("server_public.pem", "rb") as f:
        keys["server_public"] = RSA.import_key(f.read())
    return keys


def main():
    server_ip = input("Enter the server IP or name: ").strip()
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    keys = load_keys(username)
    rsa_cipher = PKCS1_OAEP.new(keys['server_public'])
    credentials = f"{username};{password}".encode()
    encrypted = rsa_cipher.encrypt(credentials)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 13000))
    client_socket.sendall(encrypted)
    response = client_socket.recv(4096)

    if response == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        client_socket.close()
        return
    
    private_cipher = PKCS1_OAEP.new(keys['client_private'])
    sym_key = private_cipher.decrypt(response)
    aes = AES.new(sym_key, AES.MODE_ECB)
    ok_msg = aes.encrypt(pad(b"OK", AES.block_size))
    send_framed(client_socket, aes.encrypt(ok_msg))


if __name__ == "__main__":
    main()