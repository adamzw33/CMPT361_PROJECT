# Client_enhanced.py

import socket
import sys
import os
import glob
import datetime
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

PORT = 13000
AES_BLOCK = AES.block_size
FRAME_LEN_BYTES = 8

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            return None
        data += part
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

def load_client_keys(username):
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
    # password is not used in enhanced protocol, keep prompt for backwards compatibility
    _ = input("Enter your password (not used in enhanced auth): ").strip()

    # load server public key (needed to encrypt the initial username and later signature)
    try:
        with open("server_public.pem", "rb") as f:
            server_pub = RSA.import_key(f.read())
    except FileNotFoundError:
        print("Missing server_public.pem in this folder. Terminating.")
        return
    rsa_server = PKCS1_OAEP.new(server_pub)
    # initial block: encrypt username (server will decrypt and issue nonce)
    encrypted_user = rsa_server.encrypt(username.encode())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, PORT))
    except Exception as e:
        print("Connection failed:", e)
        return

    # send encrypted username
    client_socket.sendall(encrypted_user)

    try:
        keys = load_client_keys(username)
    except FileNotFoundError:
        print(f"Missing {username}_private.pem or {username}_public.pem in this folder. Terminating.")
        client_socket.close()
        return

    client_pub = keys["client_public"]
    client_priv = keys["client_private"]
    client_key_size = client_priv.size_in_bytes()
    server_key_size = keys["server_public"].size_in_bytes()

    # receive the encrypted nonce (fixed size equal to client public key modulus)
    enc_nonce = recv_all(client_socket, client_key_size)
    if not enc_nonce or len(enc_nonce) != client_key_size:
        client_socket.close()
        print("Failed to receive server nonce. Terminating.")
        return

    # decrypt nonce with client private key
    try:
        client_priv_cipher = PKCS1_OAEP.new(client_priv)
        nonce = client_priv_cipher.decrypt(enc_nonce)
    except Exception:
        client_socket.close()
        print("Failed to decrypt server nonce. Terminating.")
        return

    # sign the nonce using client private key (pkcs1_15, SHA256)
    try:
        h = SHA256.new(nonce)
        signature = pkcs1_15.new(client_priv).sign(h)
    except Exception:
        client_socket.close()
        print("Failed to create signature. Terminating.")
        return

    # encrypt signature with server public key (so only server can read it)
    sig_encrypted = rsa_server.encrypt(signature)
    if len(sig_encrypted) != server_key_size:
        # sanity check
        client_socket.close()
        print("Signature packet size mismatch. Terminating.")
        return

    # send signature encrypted
    client_socket.sendall(sig_encrypted)

    # at this point server will verify signature. on success server sends RSA-encrypted AES key (fixed size server_key_size)
    response = recv_all(client_socket, server_key_size)
    if not response or len(response) != server_key_size:
        client_socket.close()
        print("Failed to receive symmetric key. Terminating.")
        return

    # decrypt symmetric key with client private
    try:
        # server encrypted AES key using client public; decrypt with client private
        sym_key = client_priv_cipher.decrypt(response)
    except Exception:
        client_socket.close()
        print("Failed to decrypt symmetric key. Terminating.")
        return

    aes = AES.new(sym_key, AES.MODE_ECB)

    # send framed encrypted OK
    ok_msg = pad(b"OK", AES_BLOCK)
    send_framed(client_socket, aes.encrypt(ok_msg))

    # menu loop (same as original)
    while True:
        framed_menu = recv_framed(client_socket)
        if framed_menu is None:
            break
        try:
            menu = unpad(aes.decrypt(framed_menu), AES_BLOCK).decode()
        except:
            break
        print(menu, end="")

        choice = input().strip()
        send_framed(client_socket, aes.encrypt(pad(choice.encode(), AES_BLOCK)))

        if choice == "1":
            framed = recv_framed(client_socket)
            if framed is None:
                break
            try:
                _prompt = unpad(aes.decrypt(framed), AES_BLOCK).decode()
            except:
                break
            dests = input("Enter destinations (separated by ;): ").strip()
            title = input("Enter title: ").strip()
            load_choice = input("Would you like to load contents from a file?(Y/N) ").strip().upper()
            if load_choice == "Y":
                fname = input("Enter filename: ").strip()
                try:
                    with open(fname, "r", encoding="utf-8") as fh:
                        content = fh.read()
                except:
                    content = ""
            else:
                content = input("Enter message contents: ")
            if len(title) > 100:
                print("Title too long. Aborting send.")
                continue
            if len(content) > 1000000:
                print("Content too large. Aborting send.")
                continue
            msg = []
            msg.append(f"From: {username}")
            msg.append(f"To: {dests}")
            msg.append(f"Title: {title}")
            msg.append(f"Content Length: {len(content)}")
            msg.append("Content:")
            msg.append(content)
            full_msg = "\n".join(msg)
            send_framed(client_socket, aes.encrypt(pad(full_msg.encode(), AES_BLOCK)))
            framed_resp = recv_framed(client_socket)
            if framed_resp is None:
                break
            try:
                resp = unpad(aes.decrypt(framed_resp), AES_BLOCK).decode()
            except:
                break
            if resp.startswith("ERROR"):
                print(resp)
            else:
                print("The message is sent to the server.")
            continue

        elif choice == "2":
            framed_list = recv_framed(client_socket)
            if framed_list is None:
                break
            try:
                payload = unpad(aes.decrypt(framed_list), AES_BLOCK).decode()
            except:
                break
            print(payload)
            send_framed(client_socket, aes.encrypt(pad(b"OK", AES_BLOCK)))
            continue

        elif choice == "3":
            framed_req = recv_framed(client_socket)
            if framed_req is None:
                break
            try:
                req = unpad(aes.decrypt(framed_req), AES_BLOCK).decode()
            except:
                break
            if req.strip() == "the server request email index":
                idx = input("Enter the email index you wish to view: ").strip()
                send_framed(client_socket, aes.encrypt(pad(idx.encode(), AES_BLOCK)))
                framed_email = recv_framed(client_socket)
                if framed_email is None:
                    break
                try:
                    email = unpad(aes.decrypt(framed_email), AES_BLOCK).decode()
                except:
                    break
                print(email)
            else:
                continue

        else:
            print("The connection is terminated with the server.")
            client_socket.close()
            return

    client_socket.close()

if __name__ == "__main__":
    main()