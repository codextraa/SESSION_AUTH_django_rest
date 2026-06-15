from rest_framework import serializers


class BaseRecaptchaSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Base serializer for handling reCAPTCHA tokens and request context validation.
    """

    recaptcha_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The Recaptcha token to be used in subsequent requests.",
        error_messages={
            "required": "Missing reCAPTCHA token.",
            "blank": "Missing reCAPTCHA token.",
            "null": "Missing reCAPTCHA token.",
        },
    )
    recaptcha_version = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The Recaptcha version to be used in subsequent requests.",
        error_messages={
            "required": "Missing reCAPTCHA version.",
            "blank": "Missing reCAPTCHA version.",
            "null": "Missing reCAPTCHA version.",
        },
    )

    def validate(self, attrs):
        request = self.context.get("request")
        if not request:
            raise serializers.ValidationError(
                {"error": "Internal server context error."}
            )

        user_agent = request.META.get("HTTP_USER_AGENT", "")
        if not user_agent:
            raise serializers.ValidationError(
                {"user_agent": "Missing User Agent Header."}
            )

        user_ip = request.META.get(
            "HTTP_X_FORWARDED_FOR", request.META.get("HTTP_X_REAL_IP", "")
        )
        if not user_ip:
            raise serializers.ValidationError({"user_ip": "Missing User IP Address."})

        if "," in user_ip:
            user_ip = user_ip.split(",")[0].strip()

        attrs["user_agent"] = user_agent
        attrs["user_ip"] = user_ip

        return attrs


class RecaptchaRequestSerializer(BaseRecaptchaSerializer):
    """
    Extends the base reCAPTCHA serializer to include the expected_action field.
    """

    expected_action = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="Client's action in the frontend to be used in subsequent requests.",
        error_messages={
            "required": "Action is required.",
            "blank": "Action is required.",
            "null": "Action is required.",
        },
    )


class LoginRequestSerializer(BaseRecaptchaSerializer):
    """
    Handles Login credentials AND inherits the base reCAPTCHA validations/fields.
    """

    email_or_username = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The email or username of the user to log in.",
        error_messages={
            "required": "Email or username is required.",
            "blank": "Email or username is required.",
            "null": "Email or username is required.",
        },
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        allow_null=False,
        allow_blank=False,
        help_text="The password of the user to log in.",
        error_messages={
            "required": "Password is required.",
            "blank": "Password is required.",
            "null": "Password is required.",
        },
    )