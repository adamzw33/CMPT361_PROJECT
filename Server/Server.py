import socket
import os
import json
import glob
import datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PORT = 13000

DB_PATH = "user_pass.json" #setting the json database for later calls

try:
    with open(DB_PATH, "r", encoding="utf-8") as f:
        database = json.load(f)
        if not isinstance(database, dict):
            database = {}
except (FileNotFoundError, json.JSONDecodeError):
    database = {}

def load_keys():
    keys = {}
    with open("server_private.pem", "rb") as f:
        keys["server_private"] = RSA.import_key(f.read())
    with open("server_public.pem", "rb") as f:
        keys["server_public"] = RSA.import_key(f.read())
    for i in range(1, 6):
        name = f"client{i}"
        with open(f"{name}_public.pem", "rb") as f:
            keys[f"{name}_public"] = RSA.import_key(f.read())
    return keys

def load_user_password():
    with open("user_pass.json", "r") as f:
        return json.load(f)

def handle_client(conn, addr, keys, user_pass):
    private_cipher = PKCS1_OAEP.new(keys['server_private'])

    encrypted_data = conn.recv(4096)
    if not encrypted_data:
        conn.close()
        return
    
    try:
        decrypted = private_cipher.decrypt(encrypted_data).decode()
        username, password = decrypted.split(';')
    except:
        conn.sendall(b"Invalid username or password.")
        conn.close()
        return
    if username not in user_pass or user_pass[username] != password:
        conn.sendall(b"Invalid username or password.")
        conn.close()
        return
    
    client_pub = keys[f"{username}_public"]
    pub_cipher = PKCS1_OAEP.new(client_pub)

    sym_key = os.urandom(32)

    encrypted_sym = pub_cipher.encrypt(sym_key)
    conn.sendall(encrypted_sym)

    from Crypto.Cipher import AES
    aes = AES.new(sym_key, AES.MODE_ECB)
    ok_msg = aes.decrypt(conn.recv(4096))

    conn.close()


def main():

    # Create the server socket (IPv4, TCP)
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', PORT))
        serverSocket.listen(5)
    except Exception as e:
        print("Server socket error:", e)
        sys.exit(1)