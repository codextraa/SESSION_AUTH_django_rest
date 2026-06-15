from rest_framework import serializers


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
