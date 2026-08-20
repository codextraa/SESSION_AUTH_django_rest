from django.conf import settings
from django.core.cache import cache
from .encryption import generate_hash_key, encrypt_data, decrypt_data


def get_cache_data(prefix, token):
    """Decrypt and return the cache data from Redis"""
    hashed_key = generate_hash_key(token)
    encrypted_data = cache.get(f"{prefix}:{hashed_key}")

    if not encrypted_data:
        return {"error": "Invalid Token"}

    return {
        "hashed_key": hashed_key,
        "decrypted_data": decrypt_data(encrypted_data),
    }


def set_cache_data(prefix, raw_cache_data, object_type, user_id=None):
    """Encrypt and store the cache data in Redis"""

    encrypt_obj = encrypt_data(raw_cache_data, object_type)

    if prefix == "pre-auth-otp":
        main_cache_timeout = settings.PRE_AUTH_OTP_TTL
        cooldown_cache_timeout = settings.OTP_COOLDOWN_TTL
    else:
        main_cache_timeout = settings.LINK_EXPIRY_TTL
        cooldown_cache_timeout = settings.LINK_COOLDOWN_TTL

    cache.set(
        f"{prefix}:{encrypt_obj["hashed_key"]}",
        encrypt_obj["encrypted_data"],
        timeout=main_cache_timeout,
    )

    if user_id:
        user_lock_key = generate_hash_key(user_id)
        cache.set(
            f"{prefix}-cooldown:{user_lock_key}",
            True,
            timeout=cooldown_cache_timeout,
        )

    return str(encrypt_obj["token"])
