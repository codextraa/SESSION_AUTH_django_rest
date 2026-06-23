import hashlib
import json
import secrets
from django.core.cache import cache
from django.conf import settings
from cryptography.fernet import Fernet


def generate_cache_key(data):
    """Hashes identifiers so raw data aren't stored naked in Redis."""
    encoded_data = str(data).encode()  # Convert to bytes
    # Hash into 256 bits and transform into lower-case, 64-character hexadecimal string for Redis key
    hashed_key = hashlib.sha256(encoded_data).hexdigest()
    return hashed_key


def encrypt_and_set_cache_data(raw_cache_obj, prefix, ttl, obj=True):
    """
    Hashes the incoming raw data, encrypts it, and stores it in Redis
    and returns the hashed token
    """
    try:
        raw_pre_auth_token = secrets.token_urlsafe(32)  # Generate a random token
        hashed_key = generate_cache_key(raw_pre_auth_token)

        cipher_suite = Fernet(
            settings.ENCRYPTION_KEY.encode()
        )  # Fernet key converted to bytes
        string_data = raw_cache_obj
        if obj:
            string_data = json.dumps(raw_cache_obj)  # Convert object to string
        encoded_data = string_data.encode()  # Convert to bytes
        encrypted_bytes = cipher_suite.encrypt(
            encoded_data
        )  # Encrypt the encoded data using fernet key
        encrypted_data = encrypted_bytes.decode()  # Convert to Base64 string

        cache.set(f"{prefix}:{hashed_key}", encrypted_data, timeout=ttl)

        return raw_pre_auth_token, None
    except Exception as e:  # pylint: disable=W0718
        return None, e


def decrypt_and_get_cache_data(raw_pre_auth_token, prefix, obj=True):
    """
    Hashes the incoming raw token, pulls the encrypted block from Redis,
    decrypts it, and returns the object
    """
    try:
        hashed_key = generate_cache_key(raw_pre_auth_token)

        encrypted_data = cache.get(f"{prefix}:{hashed_key}")  # Get the encrypted block

        if not encrypted_data:
            return None, "Invalid Pre Auth Token"
        
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

        return decrypted_data, None
    except Exception as e:  # pylint: disable=W0718
        return None, e
