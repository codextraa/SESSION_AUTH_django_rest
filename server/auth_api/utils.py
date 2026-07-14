from django.conf import settings
from django.core.cache import cache
from server.utils.encryption import (
    generate_cache_key,
    encrypt_and_set_cache_data,
    decrypt_and_get_cache_data,
)


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


def set_first_and_last_name(details):
    first_name = details.get("first_name", "").strip()
    last_name = details.get("last_name", "").strip()

    if not first_name:
        fallback_name = details.get("fullname") or details.get("username") or "User"
        name_parts = fallback_name.strip().split()
        if len(name_parts) == 1:
            first_name = name_parts[0]
        elif len(name_parts) > 1:
            first_name = name_parts[0]
            last_name = " ".join(name_parts[1:])

    return first_name, last_name


def set_profile_image(backend_name, user, response):
    """
    Extracts and assigns the provider's profile image URL.
    """
    profile_img_str = str(user.profile_img) if user.profile_img else ""
    profile_img_url = None

    if backend_name == "google-oauth2":
        google_profile_img = response.get("picture")
        if google_profile_img:
            profile_img_url = google_profile_img.replace("=s96-c", "=s720-c")
    elif backend_name == "facebook":
        facebook_profile_img = response.get("picture")
        if isinstance(facebook_profile_img, dict) and "data" in facebook_profile_img:
            profile_img_url = facebook_profile_img["data"]["url"]
    elif backend_name == "github":
        profile_img_url = response.get("avatar_url")
    elif backend_name == "linkedin-openidconnect":
        profile_img_url = response.get("picture")
    elif backend_name in ["microsoft-graph", "amazon", "apple-id"]:
        profile_img_url = "profile_images/default.png"

    if profile_img_url and profile_img_url != profile_img_str:
        user.profile_img = profile_img_url

    return user


def create_otp(user_id):
    """
    Generates an OTP and send it to the user's email.
    Encrypts the minimal cache payload (user_id & otp) using a custom key.
    Returns the raw pre-auth token to the frontend.
    """
    OTP = "000000"  # remember to convert it to string during actual implementation
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
            raw_cache_obj, "pre_auth", settings.PRE_AUTH_OTP_TTL
        )

        if error:
            raise error

        user_lock_key = generate_cache_key(user_id)
        cache.set(
            f"otp_cooldown:{user_lock_key}",
            True,
            timeout=settings.OTP_COOLDOWN_TTL,
        )

        return {
            "success": True,
            "pre_auth_token": raw_pre_auth_token,
        }

    return {"success": False, "pre_auth_token": None}


def verify_otp(raw_pre_auth_token, user_otp):
    """
    verify the OTP given by the user.
    Decrypts the minimal cache payload (user_id & otp) using a custom key.
    Returns user id.
    """
    decrypted_data, error = decrypt_and_get_cache_data(raw_pre_auth_token, "pre_auth")

    if error:
        return {
            "error": error,
        }

    hashed_pre_auth_key = generate_cache_key(raw_pre_auth_token)
    invalid_otp_key = f"invalid_otp:{hashed_pre_auth_key}"

    if user_otp != decrypted_data["otp"]:
        invalid_otp_cache_key = cache.get(invalid_otp_key)

        if invalid_otp_cache_key is not None:
            _ = cache.incr(invalid_otp_key)
        else:
            cache.set(
                invalid_otp_key,
                1,
                timeout=settings.INVALID_OTP_COOLDOWN_TTL,
            )

        return {"error": "Invalid OTP"}

    cache.delete(invalid_otp_key)

    user_lock_key = generate_cache_key(decrypted_data["user_id"])
    cache.delete(f"otp_cooldown:{user_lock_key}")

    return {
        "user_id": decrypted_data["user_id"],
    }
