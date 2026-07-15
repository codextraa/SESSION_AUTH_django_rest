from django.contrib.auth import get_user_model
from social_core.exceptions import AuthException
from server.utils.exception import ForbiddenValidationError
from core_db.utils import generate_random_username, generate_random_password
from .validation_serializers import validate_user_attributes
from .utils import set_profile_image, set_first_and_last_name

User = get_user_model()


def login_or_signup(backend, details, *args, user=None, **kwargs):
    """
    Evaluates the user state, executes strict custom validations before authentication,
    and determines whether profile updating should be permitted.
    """
    if user:  # if user already authenticated
        error_msg = validate_user_attributes(user)
        if error_msg:
            raise ForbiddenValidationError({"error": error_msg})
        return {"user": user, "is_new": False, "is_update": False}

    email = details.get("email")
    if not email:
        raise AuthException(
            backend, "An email address is required from the authentication provider."
        )

    email = email.lower()

    try:
        existing_user = User.objects.get(email=email)

        error_msg = validate_user_attributes(existing_user)
        if error_msg:
            raise ForbiddenValidationError({"error": error_msg})

        is_matching_provider = existing_user.auth_provider in backend.name

        return {
            "user": existing_user,
            "is_new": False,
            "is_update": is_matching_provider,
        }

    except User.DoesNotExist:
        return {"user": None, "is_new": True, "is_update": False}


def create_custom_user(
    backend,
    details,
    response,
    *args,
    user=None,
    is_new=False,
    is_update=False,
    **kwargs,
):  # pylint: disable=R0913, R0917
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

    first_name, last_name = set_first_and_last_name(details)

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

    new_user = set_profile_image(backend.name, new_user, response)

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
):  # pylint: disable=R0913, R0917
    """
    Handles mutable profile attribute synchronization exclusively
    for native social return.
    """
    if not user or not is_update:
        return {"user": user, "is_new": is_new, "is_update": is_update}

    has_changed = False

    new_first_name, new_last_name = set_first_and_last_name(details)

    if new_first_name and user.first_name != new_first_name:
        user.first_name = new_first_name
        has_changed = True

    if new_last_name and user.last_name != new_last_name:
        user.last_name = new_last_name
        has_changed = True

    old_img_str = str(user.profile_img) if user.profile_img else ""

    user = set_profile_image(backend.name, user, response)

    new_img_str = str(user.profile_img) if user.profile_img else ""
    if old_img_str != new_img_str:
        has_changed = True

    if has_changed:
        user.save()

    return {
        "user": user,
        "is_new": is_new,
        "is_update": is_update,
    }
