import os
from Crypto.PublicKey import RSA

def write_key(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def generate_rsa_pair(prefix):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    write_key(f"{prefix}_private.pem", private_key)
    write_key(f"{prefix}_public.pem", public_key)

def main():
    generate_rsa_pair("server")

    for i in range(1, 6):
        username = f"client{i}"
        generate_rsa_pair(username)

if __name__ == "__main__":
    main()