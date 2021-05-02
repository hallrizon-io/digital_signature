import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def get_file_hash(file_name: str):
    h = SHA256.new()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)

    return h


def sign_file_hash(private_key, file_hash: hash):
    signature = pkcs1_15.new(private_key).sign(file_hash)

    return signature


if __name__ == '__main__':
    # Generate new private key or use generated private key.
    key = RSA.generate(1024, os.urandom)

    # Get public key from private
    pubkey = key.publickey()

    file_hash = get_file_hash('example_file.txt')
    signature = sign_file_hash(private_key=key, file_hash=file_hash)

    # Send to user public key and signature
    # User must myself calculate a hash of file
    pkcs1_15.new(pubkey).verify(file_hash, signature)

    # Will raise exception because file hash is incorrect
    pkcs1_15.new(pubkey).verify(SHA256.new(b'test'), signature)  # raise ValueError("Invalid signature")
