from rest_framework import serializers
from django.conf import settings
from django.core.cache import cache
from server.utils.exception import ForbiddenValidationError
from server.utils.encryption import generate_cache_key


class ValidUserSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validates an authenticated user object provided via context against rules.
    Also handles failed login attempt accounting and brute-force lockouts.
    """

    def validate(self, attrs):
        user = self.context.get("user")
        request = self.context.get("request")

        if not user:  # Wrong Password
            user_obj = user_obj = (
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

                    raise serializers.ValidationError(
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
                    raise serializers.ValidationError(
                        {
                            "error": (
                                f"Invalid credentials. You have {remaining_attempts}"
                                " more attempt(s) before your account is deactivated."
                            )
                        },
                    )

            raise serializers.ValidationError({"error": "Invalid credentials"})

        if user.auth_provider != "email":
            raise ForbiddenValidationError(
                {
                    "error": (
                        "This process cannot be used, "
                        f"as user is created using {user.auth_provider}"
                    )
                }
            )

        if not user.is_email_verified:
            raise ForbiddenValidationError(
                {"error": "Email is not verified. You must verify your email first"}
            )

        attrs["user"] = user
        return attrs
