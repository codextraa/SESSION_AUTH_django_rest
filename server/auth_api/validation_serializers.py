from rest_framework import serializers
from django.conf import settings
from django.core.cache import cache
from server.utils.exception import BadRequestValidationError, ForbiddenValidationError
from server.utils.encryption import generate_cache_key


def validate_user_attributes(user, endpoint):
    if user.auth_provider != "email" and endpoint == "login":
        return f"This process cannot be used, as user is created using {user.auth_provider}"

    if not user.is_active:
        return "Account has been deactivated. Contact your admin"

    if not user.is_email_verified:
        return "Email is not verified. You must verify your email first"

    return None


class ValidUserSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validates an authenticated user object provided via context against rules.
    Also handles failed login attempt accounting and brute-force lockouts.
    """

    def validate(self, attrs):  # pylint: disable=R0912
        user = self.context.get("user")
        request = self.context.get("request")

        if not user:  # Wrong Password
            user_obj = (
                getattr(request, "authenticated_user_obj", None) if request else None
            )

            if user_obj:
                if not user_obj.is_active:
                    raise ForbiddenValidationError(
                        {"error": "Account has been deactivated. Contact your admin"}
                    )

                hashed_user_key = generate_cache_key(user_obj.id)
                failed_attempts_key = f"login_failures:{hashed_user_key}"

                failed_attempts = cache.get(failed_attempts_key)

                if failed_attempts is not None:
                    failed_attempts = cache.incr(failed_attempts_key)
                else:
                    failed_attempts = 1
                    cache.set(
                        failed_attempts_key,
                        failed_attempts,
                        timeout=settings.LOGIN_FAILURE_ATTEMPT_TTL,
                    )  # 1 hour

                # Lock account
                if failed_attempts >= settings.MAX_LOGIN_FAILURE_LIMIT:
                    if user_obj.is_superuser:
                        user_obj.is_email_verified = False
                        user_obj.save()
                    else:
                        user_obj.is_active = False
                        user_obj.save()

                    raise BadRequestValidationError(
                        {
                            "error": (
                                "Invalid credentials. Your account has been deactivated."
                                " Contact an admin."
                            )
                        },
                    )

                # Warn user
                if failed_attempts >= 3:
                    remaining_attempts = (
                        settings.MAX_LOGIN_FAILURE_LIMIT - failed_attempts
                    )
                    raise BadRequestValidationError(
                        {
                            "error": (
                                f"Invalid credentials. You have {remaining_attempts}"
                                " more attempt(s) before your account is deactivated."
                            )
                        },
                    )
            else:
                # Dummy key for burning expected CPU cycles to neutralize timing attacks
                dummy_hash_key = generate_cache_key("ghost_user")
                dummy_key = f"ghost_failures:{dummy_hash_key}"

                dummy_attempts = cache.get(dummy_key)
                if dummy_attempts is not None:
                    _ = cache.incr(dummy_key)
                else:
                    cache.set(dummy_key, 1, timeout=settings.DUMMY_COOLDOWN_TTL)

            raise BadRequestValidationError({"error": "Invalid credentials"})

        error = validate_user_attributes(user, "login")

        if error:
            raise ForbiddenValidationError({"error": error})

        attrs["user"] = user
        return attrs
