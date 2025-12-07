import socket
import sys
import os
import glob
import datetime
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
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
    password = input("Enter your password: ").strip()

    # Load server public key (must be present in client folder)
    try:
        with open("server_public.pem", "rb") as f:
            server_pub = RSA.import_key(f.read())
    except FileNotFoundError:
        print("Missing server_public.pem in this folder. Terminating.")
        return

    rsa_cipher = PKCS1_OAEP.new(server_pub)
    credentials = f"{username};{password}".encode()
    encrypted = rsa_cipher.encrypt(credentials)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, PORT))
    except Exception as e:
        print("Connection failed:", e)
        return

    # send credentials as fixed-size RSA block (client used server public key)
    client_socket.sendall(encrypted)

    # initial receive: may be short error message or RSA-encrypted AES key
    initial = client_socket.recv(4096)
    if not initial:
        client_socket.close()
        return

    # server uses exact text "Invalid username or password" for errors
    if initial == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        client_socket.close()
        return

    # load client private key now (must be in the client's folder)
    try:
        with open(f"{username}_private.pem", "rb") as f:
            client_priv = RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Missing {username}_private.pem in this folder. Terminating.")
        client_socket.close()
        return

    client_key_size = client_priv.size_in_bytes()

    # if initial is shorter than full RSA ciphertext, read remaining bytes
    if len(initial) < client_key_size:
        rest = recv_all(client_socket, client_key_size - len(initial))
        if rest is None:
            print("Error: incomplete symmetric key packet. Terminating.")
            client_socket.close()
            return
        response = initial + rest
    else:
        response = initial

    # If server could have sent a short error (unlikely now), check again
    if response == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        client_socket.close()
        return

    # decrypt symmetric key using client's private key
    try:
        priv_cipher = PKCS1_OAEP.new(client_priv)
        sym_key = priv_cipher.decrypt(response)
    except Exception:
        print("Failed to decrypt symmetric key. Terminating.")
        client_socket.close()
        return

    aes = AES.new(sym_key, AES.MODE_ECB)

    # send framed encrypted OK
    ok_msg = pad(b"OK", AES_BLOCK)
    send_framed(client_socket, aes.encrypt(ok_msg))

    # menu loop
    while True:
        framed_menu = recv_framed(client_socket)
        if framed_menu is None:
            break
        try:
            menu = unpad(aes.decrypt(framed_menu), AES_BLOCK).decode()
        except Exception:
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
            except Exception:
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