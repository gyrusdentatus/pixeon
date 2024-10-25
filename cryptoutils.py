# cryptoutils.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os
from nacl.signing import SigningKey

def encrypt_message(message, public_key):
    """
    Encrypt a message using the recipient's RSA public key.
    """
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted_message, private_key):
    """
    Decrypt a message using the recipient's RSA private key.
    """
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def sign_message(message, signing_key):
    """
    Sign a message using the sender's signing key.
    """
    signed = signing_key.sign(message)
    return signed

def verify_signature(signed_message, verify_key):
    """
    Verify the signature of a signed message.
    """
    try:
        verified_message = verify_key.verify(signed_message)
        return verified_message
    except exceptions.BadSignatureError as e:
        raise e
