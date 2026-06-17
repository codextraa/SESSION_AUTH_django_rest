import string
import secrets
from django.conf import settings
from django.core.cache import cache
from server.utils.encryption import (
    generate_cache_key,
    encrypt_and_set_cache_data,
)


def create_random_password(length=16):
    """
    Generate a cryptographically secure random password of the given length.
    Ensures at least one uppercase letter, one lowercase letter, one digit,
    and one special character are included in the password.
    """
    if length < 4:
        raise ValueError(
            "Password length must be at least 4 characters to meet the requirements"
        )

    # Define the character sets
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    punctuation = string.punctuation

    # Ensure at least one of each character type
    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(punctuation),
    ]

    # Fill the rest of the password length with random characters from all sets
    alphabet = lower + upper + digits + punctuation
    password += [secrets.choice(alphabet) for _ in range(length - 4)]

    # Shuffle the password to mix the characters
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def get_user_role(user):
    """Get user role."""
    user_groups = user.groups.all()

    if user_groups.filter(name="Default").exists():
        user_role = "Default"
    elif user_groups.filter(name="Admin").exists():
        user_role = "Admin"
    elif user_groups.filter(name="Superuser").exists():
        user_role = "Superuser"
    else:
        user_role = "UnAuthorized"

    return user_role


def create_otp(user_id):
    """
    Generates an OTP and send it to the user's email.
    Encrypts the minimal cache payload (user_id & otp) using a custom key.
    Returns the raw pre-auth token to the frontend.
    """
    OTP = 000000
    otp_email_sent = True

    # ? Will be implemented during email workflows
    # OTP = EmailOtp.generate_otp()
    # otp_email_sent = EmailOtp.send_email_otp(email, otp)

    # Check if the email was sent
    if otp_email_sent:
        raw_cache_obj = {
            "user_id": user_id,
            "otp": OTP,
        }
        raw_pre_auth_token, error = encrypt_and_set_cache_data(
            raw_cache_obj, "pre_auth", settings.OTP_TTL
        )

        if error:
            raise error

        user_lock_key = generate_cache_key(user_id)
        cache.set(
            f"otp_cooldown:{user_id}:{user_lock_key}",
            True,
            timeout=settings.OTP_COOLDOWN_TTL,
        )

        return {
            "success": True,
            "pre_auth_token": raw_pre_auth_token,
        }

    return {"success": False, "pre_auth_token": None}
