from rest_framework import serializers


class ValidUserSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validates an authenticated user object provided via context against rules.
    """

    def validate(self, attrs):
        user = self.context.get("user")

        if not user:
            raise serializers.ValidationError({"error": "Invalid credentials"})

        if user.auth_provider != "email":
            raise serializers.ValidationError(
                {
                    "error": (
                        "This process cannot be used, "
                        f"as user is created using {user.auth_provider}"
                    )
                }
            )

        if not user.is_email_verified:
            raise serializers.ValidationError(
                {"error": "Email is not verified. You must verify your email first"}
            )

        if not user.is_active:
            raise serializers.ValidationError(
                {"error": "Account is deactivated. Contact your admin"}
            )

        attrs["user"] = user
        return attrs