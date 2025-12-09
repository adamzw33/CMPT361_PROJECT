# Server_enhanced.py

import socket
import os
import json
import glob
import datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

PORT = 13000
DB_PATH = "user_pass.json"
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

def load_keys():
    keys = {}
    with open("server_private.pem", "rb") as f:
        keys["server_private"] = RSA.import_key(f.read())
    with open("server_public.pem", "rb") as f:
        keys["server_public"] = RSA.import_key(f.read())
    for i in range(1, 6):
        name = f"client{i}"
        try:
            with open(f"{name}_public.pem", "rb") as f:
                keys[f"{name}_public"] = RSA.import_key(f.read())
        except FileNotFoundError:
            pass
    return keys

def load_user_password():
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def ensure_client_folder(username):
    if not os.path.isdir(username):
        os.mkdir(username)

def encrypt_aes(aes, plaintext):
    return aes.encrypt(pad(plaintext, AES_BLOCK))

def decrypt_aes(aes, ciphertext):
    return unpad(aes.decrypt(ciphertext), AES_BLOCK)

def handle_send_email(parsed_msg, src_username):
    lines = parsed_msg.splitlines()
    header_map = {}
    content_index = None
    for i, line in enumerate(lines):
        if line.startswith("From:"):
            header_map["From"] = line[len("From:"):].strip()
        elif line.startswith("To:"):
            header_map["To"] = line[len("To:"):].strip()
        elif line.startswith("Title:"):
            header_map["Title"] = line[len("Title:"):].strip()
        elif line.startswith("Content Length:"):
            header_map["Content Length"] = line[len("Content Length:"):].strip()
        elif line == "Content:":
            content_index = i + 1
            break
    content = "\n".join(lines[content_index:]) if content_index is not None else ""
    try:
        clen = int(header_map.get("Content Length", str(len(content))))
    except:
        return False, "Invalid Content Length"
    if len(header_map.get("Title", "")) > 100:
        return False, "Title too long"
    if clen != len(content):
        return False, "Content length mismatch"
    if len(content) > 1000000:
        return False, "Content too large"

    dests = header_map.get("To", "")
    dest_list = [d.strip() for d in dests.split(";") if d.strip()]
    timestamp = datetime.datetime.now().isoformat()
    filename_title = header_map.get("Title", "").replace(" ", "_") or "untitled"
    saved_files = []
    for dest in dest_list:
        ensure_client_folder(dest)
        fname = f"{src_username}_{filename_title}.txt"
        fpath = os.path.join(dest, fname)
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write(f"From: {src_username}\n")
            fh.write(f"To: {dests}\n")
            fh.write(f"Time and Date: {timestamp}\n")
            fh.write(f"Title: {header_map.get('Title','')}\n")
            fh.write(f"Content Length: {clen}\n")
            fh.write("Content:\n")
            fh.write(content)
        saved_files.append(fpath)
    return True, (dest_list, clen, timestamp)

def build_inbox_list(username):
    ensure_client_folder(username)
    files = glob.glob(os.path.join(username, "*.txt"))
    entries = []
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
            from_line = next((l for l in lines if l.startswith("From:")), "").strip()
            time_line = next((l for l in lines if l.startswith("Time and Date:")), "").strip()
            title_line = next((l for l in lines if l.startswith("Title:")), "").strip()
            sender = from_line[len("From:"):].strip()
            tstamp = time_line[len("Time and Date:"):].strip()
            title = title_line[len("Title:"):].strip()
            entries.append((fpath, sender, tstamp, title))
        except:
            continue
    entries.sort(key=lambda e: e[2], reverse=True)
    return entries

def handle_client(conn, addr, keys, user_pass):
    # server RSA private cipher (used for decrypting the initial username block
    # and later to decrypt the client's signature block)
    private_cipher = PKCS1_OAEP.new(keys["server_private"])
    server_key_size_bytes = keys["server_private"].size_in_bytes()

    try:
        # === Step 1: Receive username (RSA-encrypted with server public key).
        encrypted_user = recv_all(conn, server_key_size_bytes)
        if not encrypted_user or len(encrypted_user) != server_key_size_bytes:
            conn.close()
            return

        try:
            username = private_cipher.decrypt(encrypted_user).decode().strip()
        except Exception:
            conn.sendall(b"Invalid username or password")
            conn.close()
            return

        # simple sanity: username must match known list
        if username not in user_pass:
            conn.sendall(b"Invalid username or password")
            print("The received client information:", username, "is invalid (Connection Terminated).")
            conn.close()
            return

        # === Step 2: send server nonce encrypted with client public key
        key_label = f"{username}_public"
        if key_label not in keys:
            conn.sendall(b"Invalid username or password")
            print("Missing public key for", username)
            conn.close()
            return

        client_pub = keys[key_label]
        client_pub_cipher = PKCS1_OAEP.new(client_pub)

        # generate a per-session nonce (server challenge)
        nonce = os.urandom(16)  # 16 bytes random nonce
        encrypted_nonce = client_pub_cipher.encrypt(nonce)
        # send fixed-size RSA ciphertext (no framing)
        conn.sendall(encrypted_nonce)

        # signature will be encrypted with server public key; read fixed-size RSA block
        sig_encrypted = recv_all(conn, server_key_size_bytes)
        if not sig_encrypted or len(sig_encrypted) != server_key_size_bytes:
            conn.close()
            return

        # decrypt signature with server private key
        try:
            signature = private_cipher.decrypt(sig_encrypted)
        except Exception:
            conn.close()
            return

        # verify signature using client's public key
        try:
            h = SHA256.new(nonce)
            pkcs1_15.new(client_pub).verify(h, signature)
        except Exception:
            # verification failed
            conn.sendall(b"Invalid username or password")
            print("Signature verification failed for", username)
            conn.close()
            return

        # authentication succeeded
        print("Connection Accepted and Symmetric Key Generated for client:", username)

        # === proceed with symmetric key exchange exactly as original protocol
        sym_key = os.urandom(32)
        pub_cipher = PKCS1_OAEP.new(client_pub)
        encrypted_sym = pub_cipher.encrypt(sym_key)
        conn.sendall(encrypted_sym)

        aes = AES.new(sym_key, AES.MODE_ECB)
        # receive framed encrypted OK
        framed = recv_framed(conn)
        if framed is None:
            conn.close()
            return
        try:
            ok = decrypt_aes(aes, framed)
        except Exception:
            conn.close()
            return
        if ok != b"OK":
            conn.close()
            return

        # === menu loop (same as original Server.py)
        last_list = []
        while True:
            menu = ("Select the operation:\n\n1) Create and send an email\n\n2) Display the inbox list\n\n3) Display the email contents\n\n4) Terminate the connection\n\nchoice: ")
            send_framed(conn, encrypt_aes(aes, menu.encode()))

            framed_choice = recv_framed(conn)
            if framed_choice is None:
                break
            try:
                choice = decrypt_aes(aes, framed_choice).decode().strip()
            except:
                break

            if choice == "1":
                send_framed(conn, encrypt_aes(aes, b"Send the email"))
                framed_email = recv_framed(conn)
                if framed_email is None:
                    break
                try:
                    email_text = decrypt_aes(aes, framed_email).decode()
                except:
                    break
                ok, info = handle_send_email(email_text, username)
                if not ok:
                    err = f"ERROR: {info}"
                    send_framed(conn, encrypt_aes(aes, err.encode()))
                else:
                    dest_list, clen, timestamp = info
                    dests_str = ";".join(dest_list)
                    print(f"An email from {username} is sent to {dests_str} has a content length of {clen}.")
                    send_framed(conn, encrypt_aes(aes, b"Message stored"))
                continue

            elif choice == "2":
                entries = build_inbox_list(username)
                last_list = entries
                lines = []
                lines.append("Index\tFrom\tDateTime\tTitle")
                for idx, ent in enumerate(entries, start=1):
                    _, sender, tstamp, title = ent
                    lines.append(f"{idx}\t{sender}\t{tstamp}\t{title}")
                payload = "\n".join(lines)
                send_framed(conn, encrypt_aes(aes, payload.encode()))
                framed_ok = recv_framed(conn)
                if framed_ok is None:
                    break
                try:
                    _ = decrypt_aes(aes, framed_ok)
                except:
                    break
                continue

            elif choice == "3":
                send_framed(conn, encrypt_aes(aes, b"the server request email index"))
                framed_idx = recv_framed(conn)
                if framed_idx is None:
                    break
                try:
                    idx_bytes = decrypt_aes(aes, framed_idx)
                    index = int(idx_bytes.decode().strip())
                except:
                    break
                if not last_list or index < 1 or index > len(last_list):
                    send_framed(conn, encrypt_aes(aes, b"Invalid index"))
                    continue
                fpath, sender, tstamp, title = last_list[index - 1]
                with open(fpath, "r", encoding="utf-8") as fh:
                    content = fh.read()
                send_framed(conn, encrypt_aes(aes, content.encode()))
                continue

            else:
                print(f"Terminating connection with {username}")
                conn.close()
                return

    except Exception:
        try:
            conn.close()
        except:
            pass
        return

def main():
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', PORT))
        serverSocket.listen(5)
    except Exception as e:
        print("Server socket error:", e)
        sys.exit(1)

    keys = load_keys()
    user_pass = load_user_password()

    print("The server is ready to accept connections")

    while True:
        conn, addr = serverSocket.accept()
        pid = os.fork()
        if pid == 0:
            serverSocket.close()
            handle_client(conn, addr, keys, user_pass)
            os._exit(0)
        else:
            conn.close()

if __name__ == "__main__":
    main()