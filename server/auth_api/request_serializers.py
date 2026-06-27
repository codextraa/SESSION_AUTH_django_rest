from rest_framework import serializers
from server.schema_serializers import BaseRecaptchaSerializer


class RecaptchaRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
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


class LoginRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
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


class TwoFARequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Handles 2FA credentials.
    """

    # pylint: disable=R0801
    pre_auth_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw pre-auth token to be used in subsequent requests.",
        error_messages={
            "required": "Token is required.",
            "blank": "Token is required.",
            "null": "Token is required.",
        },
    )
    # pylint: enable=R0801

    otp = serializers.IntegerField(
        required=True,
        allow_null=False,
        help_text="The One Time Password to be used in subsequent requests.",
        error_messages={
            "required": "OTP is required.",
            "null": "OTP is required.",
            "invalid": "OTP is invalid.",
        },
    )
