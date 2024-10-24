# keymanagement.py

import os
from nacl import public, encoding, signing

CONFIG_DIR = os.path.expanduser("~/.config/picsecret/")

def generate_keypair(name):
    """
    Generate a new signing key and encryption key pair and save them under ~/.config/picsecret/<name>/.

    Parameters:
        name (str): Name of the keypair (used as directory name).
    """
    # Generate signing key pair
    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    # Generate encryption key pair
    private_key = public.PrivateKey.generate()
    public_key = private_key.public_key

    # Save keys to ~/.config/picsecret/<name>/
    key_dir = os.path.join(CONFIG_DIR, name)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
        print(f"Created directory {key_dir}")
    else:
        print(f"Directory {key_dir} already exists.")

    signing_key_path = os.path.join(key_dir, 'signing_key.pem')
    verify_key_path = os.path.join(key_dir, 'verify_key.pem')
    private_key_path = os.path.join(key_dir, 'private_key.pem')
    public_key_path = os.path.join(key_dir, 'public_key.pem')

    save_key(signing_key, signing_key_path)
    save_key(verify_key, verify_key_path)
    save_key(private_key, private_key_path)
    save_key(public_key, public_key_path)

    print(f"Keys saved to {key_dir}")

def save_key(key, filepath):
    """
    Save a key to a file.

    Parameters:
        key: The key to save.
        filepath (str): The path to the file.
    """
    with open(filepath, 'wb') as f:
        f.write(key.encode(encoder=encoding.Base64Encoder))

def load_signing_key(name):
    """
    Load a signing key from the user's config directory.

    Parameters:
        name (str): Name of the keypair.

    Returns:
        nacl.signing.SigningKey: The loaded signing key.
    """
    signing_key_path = os.path.join(CONFIG_DIR, name, 'signing_key.pem')
    with open(signing_key_path, 'rb') as f:
        key_data = f.read()
    return signing.SigningKey(key_data, encoder=encoding.Base64Encoder)

def load_verify_key(name):
    """
    Load a verify key from the user's config directory.

    Parameters:
        name (str): Name of the keypair.

    Returns:
        nacl.signing.VerifyKey: The loaded verify key.
    """
    verify_key_path = os.path.join(CONFIG_DIR, name, 'verify_key.pem')
    with open(verify_key_path, 'rb') as f:
        key_data = f.read()
    return signing.VerifyKey(key_data, encoder=encoding.Base64Encoder)

def load_private_key(name):
    """
    Load a private key from the user's config directory.

    Parameters:
        name (str): Name of the keypair.

    Returns:
        nacl.public.PrivateKey: The loaded private key.
    """
    private_key_path = os.path.join(CONFIG_DIR, name, 'private_key.pem')
    with open(private_key_path, 'rb') as f:
        key_data = f.read()
    return public.PrivateKey(key_data, encoder=encoding.Base64Encoder)

def load_public_key(name):
    """
    Load a public key from the user's config directory.

    Parameters:
        name (str): Name of the keypair.

    Returns:
        nacl.public.PublicKey: The loaded public key.
    """
    public_key_path = os.path.join(CONFIG_DIR, name, 'public_key.pem')
    with open(public_key_path, 'rb') as f:
        key_data = f.read()
    return public.PublicKey(key_data, encoder=encoding.Base64Encoder)
