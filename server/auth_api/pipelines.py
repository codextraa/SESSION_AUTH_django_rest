from django.contrib.auth import get_user_model
from social_core.exceptions import AuthException
from server.utils.exception import ForbiddenValidationError
from core_db.utils import generate_random_username, generate_random_password
from .utils import validate_user_attributes, set_profile_image

User = get_user_model()


def login_or_signup(backend, details, *args, user=None, **kwargs):
    """
    Evaluates the user state via Social UID or email verification,
    executes strict custom validations before authentication,
    and determines whether profile updating should be permitted.
    """
    if user:  # if social provider already used before
        existing_user = user
    else:  # if social provider used first time
        email = details.get("email")

        if not email:
            raise AuthException(
                backend,
                "An email address is required from the authentication provider.",
            )

        email = email.lower()

        try:
            existing_user = User.objects.get(email=email)
        except User.DoesNotExist:
            return {"user": None, "is_new": True, "is_update": False}

    error_msg = validate_user_attributes(existing_user, "social_login")
    if error_msg:
        raise ForbiddenValidationError({"error": error_msg})

    is_matching_provider = existing_user.auth_provider in backend.name

    return {
        "user": existing_user,
        "is_new": False,
        "is_update": is_matching_provider,
    }


def create_custom_user(
    backend,
    details,
    response,
    *args,
    user=None,
    is_new=False,
    is_update=False,
    **kwargs,
):  # pylint: disable=R0913, R0914, R0917
    """
    Handles user instance initialization for new user
    """
    if not is_new:
        return {"user": user, "is_new": is_new, "is_update": is_update}

    email = details.get("email", "").lower()
    if not email:
        raise AuthException(
            backend, "Email identifier missing from the provider response."
        )

    first_name = details.get("first_name", "").strip()
    last_name = details.get("last_name", "").strip()

    if not first_name:
        fallback_name = details.get("fullname")
        name_parts = fallback_name.strip().split()
        if len(name_parts) == 1:
            first_name = name_parts[0]
        elif len(name_parts) > 1:
            first_name = name_parts[0]
            last_name = " ".join(name_parts[1:])

    provider_tag = backend.name.split("-")[0]

    username = generate_random_username()

    new_user = User(
        email=email,
        username=username,
        first_name=first_name,
        last_name=last_name,
        auth_provider=provider_tag,
        is_active=True,
        is_email_verified=True,
        is_two_fa=False,
        is_staff=False,
        is_superuser=False,
    )

    random_pass = generate_random_password(length=16)

    new_user.set_password(random_pass)

    new_profile_image = set_profile_image(backend.name, new_user, response)

    if new_profile_image:
        new_user.profile_img = new_profile_image

    new_user.save()

    return {
        "user": new_user,
        "is_new": False,
        "is_update": False,
    }


def update_user_details(
    backend,
    details,
    response,
    *args,
    user=None,
    is_new=False,
    is_update=False,
    **kwargs,
):  # pylint: disable=R0913, R0917, W0613
    """
    Handles mutable profile attribute synchronization exclusively
    for native social return.
    """
    if not user or not is_update:
        return {"user": user, "is_new": is_new, "is_update": is_update}

    has_changed = False

    new_profile_image = set_profile_image(backend.name, user, response)

    if new_profile_image:
        user.profile_img = new_profile_image
        has_changed = True

    if has_changed:
        user.save()

    return {
        "user": user,
        "is_new": is_new,
        "is_update": is_update,
    }
