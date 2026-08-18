import hashlib
import json
import secrets
from cryptography.fernet import Fernet
from django.conf import settings


def generate_hash_key(data):
    """Hashes identifiers so raw data aren't stored naked in Redis."""
    encoded_data = str(data).encode()  # Convert to bytes
    # Hash into 256 bits and transform into lower-case, 64-character hexadecimal string for Redis key
    hashed_key = hashlib.sha256(encoded_data).hexdigest()
    return hashed_key


def encrypt_data(raw_data, obj=True):
    """
    Hashes the incoming raw data, encrypts it and returns
    the raw token, hashed key, and encrypted data
    """
    token = secrets.token_urlsafe(32)  # Generate a random token
    hashed_key = generate_hash_key(token)

    cipher_suite = Fernet(
        settings.ENCRYPTION_KEY.encode()
    )  # Fernet key converted to bytes
    string_data = raw_data
    if obj:
        string_data = json.dumps(raw_data)  # Convert object to string
    encoded_data = string_data.encode()  # Convert to bytes
    encrypted_bytes = cipher_suite.encrypt(
        encoded_data
    )  # Encrypt the encoded data using fernet key
    encrypted_data = encrypted_bytes.decode()  # Convert to Base64 string

    return {
        "encrypted_data": encrypted_data,
        "hashed_key": hashed_key,
        "token": token,
    }


def decrypt_data(encrypted_data, obj=True):
    """
    Decrypts the incoming encrypted data, and returns the raw object
    """
    encoded_encrypted_data = encrypted_data.encode()  # Convert to bytes

    cipher_suite = Fernet(
        settings.ENCRYPTION_KEY.encode()
    )  # Fernet key converted to bytes
    decrypted_bytes = cipher_suite.decrypt(
        encoded_encrypted_data
    )  # Decrypt the encoded data using fernet key
    decrypted_data = decrypted_bytes.decode()  # Convert to Base64 string

    if obj:
        decrypted_data = json.loads(decrypted_data)  # Convert to object

    return decrypted_data
