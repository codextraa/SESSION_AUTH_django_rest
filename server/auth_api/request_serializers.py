from rest_framework import serializers

class RecaptchaRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
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
    expected_action = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The expected action to be used in subsequent requests.",
        error_messages={
            "required": "Action is required.",
            "blank": "Action is required.",
            "null": "Action is required.",
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
            raise serializers.ValidationError(
                {"user_ip": "Missing User IP Address."}
            )

        if "," in user_ip:
            user_ip = user_ip.split(",")[0].strip()

        attrs["user_agent"] = user_agent
        attrs["user_ip"] = user_ip

        return attrs


# class LoginRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
#     email_or_username = serializers.EmailField(
#         required=True,
#         help_text="The email or username of the user to log in.",
#     )
#     password = serializers.CharField(
#         required=True, 
#         write_only=True,
#         help_text="The password of the user to log in.",
#     )