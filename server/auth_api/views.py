from datetime import datetime, timedelta, timezone
from django.middleware.csrf import get_token
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample

from server.renderers import ViewRenderer
from server.utils.recaptcha import verify_recaptcha_token
from server.schema_serializers import (
    CSRFTokenResponseSerializer,
    RecaptchaRequestSerializer,
    SuccessResponseSerializer,
    ErrorResponseSerializer,
)


def extract_recaptcha_data(request):
    """Extracts recaptcha token and version from the request data and
    extracts user_agent and user_ip from the request headers."""

    recaptcha_token = request.data.get("recaptcha_token")
    if recaptcha_token is None:
        return Response(
            {"error": "Missing reCAPTCHA token."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    recaptcha_version = request.data.get("recaptcha_version")
    if recaptcha_version is None:
        return Response(
            {"error": "Missing reCAPTCHA version."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_agent = request.META.get("HTTP_USER_AGENT", "")
    if user_agent == "":
        return Response(
            {"error": "Missing User Agent."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_ip = request.META.get(
        "HTTP_X_FORWARDED_FOR", request.META.get("HTTP_X_REAL_IP", "")
    )
    if user_ip == "":
        return Response(
            {"error": "Missing User IP Address."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if "," in user_ip:
        user_ip = user_ip.split(",")[0].strip()

    return {
        "recaptcha_token": recaptcha_token,
        "recaptcha_version": recaptcha_version,
        "user_ip": user_ip,
        "user_agent": user_agent,
    }


class CSRFTokenView(APIView):
    """CSRF Token View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Get CSRF Token",
        description="Returns a CSRF token along with its expiration time.",
        tags=["Authentication"],
        request=None,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=CSRFTokenResponseSerializer,
                description="CSRF token returned",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error",
            ),
        },
        examples=[
            OpenApiExample(
                name="Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "csrf_token": "abc123def456ghi789-CSRFToken",
                    "csrf_token_expiry": "2024-07-01T12:00:00Z",
                },
            ),
            OpenApiExample(
                name="Bad Request",
                response_only=True,
                status_codes=["400"],
                value={"error": "Invalid request parameters"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        """Get Method for CSRF Token."""
        try:
            csrf_token = get_token(request)
            # Substracting a minute so that frontend request doesn't give token expired error
            csrf_token_expiry = (
                datetime.now(timezone.utc) + timedelta(days=1) - timedelta(minutes=1)
            )
            return Response(
                {
                    "csrf_token": csrf_token,
                    "csrf_token_expiry": csrf_token_expiry.isoformat(),
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:  # pylint: disable=W0718
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RecaptchaValidationView(APIView):
    """Recaptcha Validation View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Validate reCAPTCHA",
        description="Validates the provided reCAPTCHA token with Google's reCAPTCHA service.",
        tags=["Authentication"],
        request=RecaptchaRequestSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="reCAPTCHA validation successful",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA validation failed",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error",
            ),
        },
        examples=[
            OpenApiExample(
                name="Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "reCAPTCHA validation successful",
                },
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"error": "Missing reCAPTCHA token."},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA version",
                response_only=True,
                status_codes=["400"],
                value={"error": "Missing reCAPTCHA version."},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"error": "Missing User Agent."},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"error": "Missing User IP Address."},
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Reason"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Challenge Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "User failed the reCAPTCHA visual challenge."},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "High risk transaction blocked. Score: 0.3"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        """Post a request to validate reCAPTCHA.
        Returns a response with success or error message."""
        try:
            extracted_data = extract_recaptcha_data(request)

            if isinstance(extracted_data, Response):
                return extracted_data

            is_human, message = verify_recaptcha_token(
                token=extracted_data["recaptcha_token"],
                expected_action="login",
                recaptcha_version=extracted_data["recaptcha_version"],
                user_ip_address=extracted_data["user_ip"],
                user_agent=extracted_data["user_agent"],
            )

            if not is_human:
                return Response({"error": message}, status=status.HTTP_403_FORBIDDEN)

            return Response(
                {"success": message},
                status=status.HTTP_200_OK,
            )
        except Exception as e:  # pylint: disable=W0718
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
