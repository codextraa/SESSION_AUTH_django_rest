from rest_framework import serializers


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF token structure."""

    csrf_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The CSRF token to be used in subsequent requests.",
        error_messages={
            "required": "CSRF token is required.",
            "blank": "CSRF token is required.",
            "null": "CSRF token is required.",
        },
    )
    csrf_token_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="CSRF Token Expiry in ISO 8601 format",
        error_messages={
            "required": "CSRF expiration timestamp is required.",
            "invalid": "CSRF expiration timestamp is invalid.",
            "null": "CSRF expiration timestamp is required.",
        },
    )


class OTPSuccessResponse(serializers.Serializer):  # pylint: disable=W0223
    success = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="A descriptive message indicating the success of the login operation.",
        error_messages={
            "required": "Success message is required.",
            "blank": "Success message is required.",
            "null": "Success message is required.",
        },
    )
    otp = serializers.BooleanField(
        required=True,
        allow_null=False,
        help_text="A boolean field indicating whether an OTP is sent in email or not.",
        error_messages={
            "required": "OTP status is required.",
            "null": "OTP status is required.",
            "invalid": "OTP status is invalid.",
        },
    )
    user_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        help_text="A unique identifier for the user.",
        error_messages={
            "required": "User ID is required.",
            "null": "User ID is required.",
            "invalid": "User ID is invalid.",
        },
    )


class SessionSuccessResponse(CSRFTokenResponseSerializer):  # pylint: disable=W0223
    sessionid = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="A unique identifier for the user's session.",
        error_messages={
            "required": "Session ID is required.",
            "blank": "Session ID is required.",
            "null": "Session ID is required.",
        },
    )
    session_token_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="Session token expiry in ISO 8601 format.",
        error_messages={
            "required": "Session token expiry is required.",
            "invalid": "Session token expiry is invalid.",
            "null": "Session token expiry is required.",
        },
    )
    user_role = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The role of the user in the system.",
        error_messages={
            "required": "User role is required.",
            "blank": "User role is required.",
            "null": "User role is required.",
        },
    )
    user_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        help_text="A unique identifier for the user.",
        error_messages={
            "required": "User ID is required.",
            "null": "User ID is required.",
            "invalid": "User ID is invalid.",
        }
    )
