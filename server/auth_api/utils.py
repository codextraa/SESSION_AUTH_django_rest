from django.conf import settings


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


def validate_user_attributes(user, endpoint):
    if user.auth_provider != "email" and endpoint == "login":
        return (
            "This account uses social login. Please set a "
            "password first to log in with an email."
        )

    if user.is_staff and endpoint == "social_login":
        return (
            "Authentication failed. Please verify your credentials "
            "or try a different login method."
        )

    if not user.is_active:
        return "Account has been deactivated. Contact your admin"

    if not user.is_email_verified:
        return "Email is not verified. You must verify your email first"

    return None


def set_profile_image(backend_name, user, response):
    """
    Extracts and assigns the provider's profile image URL.
    """
    profile_img_str = str(user.profile_img) if user.profile_img else ""
    profile_img_url = ""

    if profile_img_str:
        is_local_path = not profile_img_str.startswith(("http://", "https://"))

        bucket_name = getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
        is_s3_bucket = bucket_name and (bucket_name in profile_img_str)

        allowed_hosts = getattr(settings, "ALLOWED_HOSTS", [])
        is_allowed_host = any(
            host.strip() in profile_img_str for host in allowed_hosts if host.strip()
        )

        if is_local_path or is_s3_bucket or is_allowed_host:
            return None

    if backend_name == "google-oauth2":
        google_profile_img = response.get("picture", "")
        if google_profile_img:
            profile_img_url = google_profile_img.replace("=s96-c", "=s720-c")
    elif backend_name == "facebook":
        facebook_profile_img = response.get("picture", "")
        if isinstance(facebook_profile_img, dict) and "data" in facebook_profile_img:
            profile_img_url = facebook_profile_img["data"]["url"]
    elif backend_name == "github":
        profile_img_url = response.get("avatar_url", "")
    elif backend_name == "linkedin-openidconnect":
        profile_img_url = response.get("picture", "")
    elif backend_name in ["microsoft-graph", "amazon", "apple-id"]:
        profile_img_url = ""

    if not profile_img_url:
        return "profile_images/default_profile.jpg"

    if profile_img_url and profile_img_url != profile_img_str:
        return profile_img_url

    return None
