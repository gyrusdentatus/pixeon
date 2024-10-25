# keymanagement.py

import os
from nacl import public, encoding, signing
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

CONFIG_DIR = os.path.expanduser("~/.config/picsecret/")

def generate_keypair(name):
    """
    Generate a new signing key and RSA key pair and save them under ~/.config/picsecret/<name>/.
    """
    # Generate signing key pair (Ed25519)
    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=None
    )
    public_key = private_key.public_key()

    # Save keys to ~/.config/picsecret/<name>/
    key_dir = os.path.join(CONFIG_DIR, name)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
        print(f"Created directory {key_dir}")
    else:
        print(f"Directory {key_dir} already exists.")

    # Save signing keys
    signing_key_path = os.path.join(key_dir, 'signing_key.pem')
    verify_key_path = os.path.join(key_dir, 'verify_key.pem')
    save_key(signing_key, signing_key_path)
    save_key(verify_key, verify_key_path)

    # Save RSA keys
    private_key_path = os.path.join(key_dir, 'private_key.pem')
    public_key_path = os.path.join(key_dir, 'public_key.pem')

    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Keys saved to {key_dir}")

def save_key(key, filepath):
    with open(filepath, 'wb') as f:
        f.write(key.encode(encoder=encoding.Base64Encoder))

def load_signing_key(name):
    signing_key_path = os.path.join(CONFIG_DIR, name, 'signing_key.pem')
    with open(signing_key_path, 'rb') as f:
        key_data = f.read()
    return signing.SigningKey(key_data, encoder=encoding.Base64Encoder)

def load_verify_key(name):
    verify_key_path = os.path.join(CONFIG_DIR, name, 'verify_key.pem')
    with open(verify_key_path, 'rb') as f:
        key_data = f.read()
    return signing.VerifyKey(key_data, encoder=encoding.Base64Encoder)

def load_private_key(name):
    private_key_path = os.path.join(CONFIG_DIR, name, 'private_key.pem')
    with open(private_key_path, 'rb') as f:
        key_data = f.read()
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=None
    )
    return private_key

def load_public_key(name):
    public_key_path = os.path.join(CONFIG_DIR, name, 'public_key.pem')
    with open(public_key_path, 'rb') as f:
        key_data = f.read()
    public_key = serialization.load_pem_public_key(
        key_data,
        backend=None
    )
    return public_key
