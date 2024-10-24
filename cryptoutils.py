# cryptoutils.py

from nacl import public, encoding, signing, exceptions

def generate_signing_key():
    """
    Generate a new Ed25519 signing key.
    """
    private_key = signing.SigningKey.generate()
    public_key = private_key.verify_key
    return private_key, public_key

def generate_encryption_key():
    """
    Generate a new Curve25519 key pair for encryption.
    """
    private_key = public.PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def encrypt_message(message, recipient_public_key):
    """
    Encrypt a message using the recipient's public key.

    Parameters:
        message (bytes): The plaintext message to encrypt.
        recipient_public_key (nacl.public.PublicKey): The recipient's public key.

    Returns:
        bytes: The encrypted message.
    """
    sealed_box = public.SealedBox(recipient_public_key)
    encrypted = sealed_box.encrypt(message)
    return encrypted

def decrypt_message(encrypted_message, private_key):
    """
    Decrypt a message using the recipient's private key.

    Parameters:
        encrypted_message (bytes): The encrypted message to decrypt.
        private_key (nacl.public.PrivateKey): The recipient's private key.

    Returns:
        bytes: The decrypted message.
    """
    unseal_box = public.SealedBox(private_key)
    decrypted = unseal_box.decrypt(encrypted_message)
    return decrypted

def sign_message(message, signing_key):
    """
    Sign a message using the sender's signing key.

    Parameters:
        message (bytes): The message to sign.
        signing_key (nacl.signing.SigningKey): The sender's signing key.

    Returns:
        bytes: The signed message.
    """
    signed = signing_key.sign(message)
    return signed

def verify_signature(signed_message, verify_key):
    """
    Verify the signature of a signed message.

    Parameters:
        signed_message (bytes): The signed message.
        verify_key (nacl.signing.VerifyKey): The sender's verify key.

    Returns:
        bytes: The original message if verification succeeds.

    Raises:
        nacl.exceptions.BadSignatureError: If the signature is invalid.
    """
    try:
        verified_message = verify_key.verify(signed_message)
        return verified_message
    except exceptions.BadSignatureError as e:
        raise e
