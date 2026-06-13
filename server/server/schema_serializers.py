from rest_framework import serializers


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF Token structure."""

    csrf_token = serializers.CharField(
        help_text="The CSRF token to be used in subsequent requests.",
    )
    csrf_token_expiry = serializers.DateTimeField(
        help_text="CSRF Token Expiry in ISO 8601 format.",
    )


class RecaptchaRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    recaptcha_token = serializers.CharField(required=True)
    recaptcha_version = serializers.CharField(required=True)


class SuccessResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard Success Response structure."""

    success = serializers.CharField(
        help_text="A descriptive message indicating the success of the operation.",
    )


class ErrorResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard Error Response structure."""

    errors = serializers.CharField(
        help_text="A descriptive error message explaining the failure or status.",
    )
