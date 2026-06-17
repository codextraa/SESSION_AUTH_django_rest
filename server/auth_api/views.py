from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.middleware.csrf import get_token
from django.core.cache import cache
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.exceptions import ValidationError, Throttled
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    PolymorphicProxySerializer,
)

from server.renderers import ViewRenderer
from server.utils.exception import ForbiddenValidationError
from server.utils.recaptcha import verify_recaptcha_token
from server.utils.encryption import generate_cache_key
from server.utils.throttles import OTPCooldownThrottle
from server.schema_serializers import (
    SuccessResponseSerializer,
    ErrorResponseSerializer,
)
from .utils import get_user_role, create_otp
from .validation_serializers import ValidUserSerializer
from .request_serializers import RecaptchaRequestSerializer, LoginRequestSerializer
from .response_serializers import (
    CSRFTokenResponseSerializer,
    OTPResponseSerializer,
    SessionResponseSerializer,
)


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
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            serializer = CSRFTokenResponseSerializer(data=raw_data)

            serializer.is_valid(raise_exception=True)

            return Response(serializer.data, status=status.HTTP_200_OK)
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
                name="Action Missing",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"expected_action": ["Action is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_ip": ["Missing User IP Address."]}},
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
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to validate reCAPTCHA.
        Returns a response with success or error message."""
        try:
            serializer = RecaptchaRequestSerializer(
                data=request.data, context={"request": request}
            )

            serializer.is_valid(raise_exception=True)

            validated_data = serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=validated_data["recaptcha_token"],
                expected_action=validated_data["expected_action"],
                recaptcha_version=validated_data["recaptcha_version"],
                user_ip_address=validated_data["user_ip"],
                user_agent=validated_data["user_agent"],
            )

            if not is_human:
                return Response({"error": message}, status=status.HTTP_403_FORBIDDEN)

            return Response(
                {"success": message},
                status=status.HTTP_200_OK,
            )
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    """Login View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [OTPCooldownThrottle, ScopedRateThrottle]
    throttle_scope = "email_otp"

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " requesting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Login to get an OTP or Session ID",
        description=(
            "Authenticates a user via credentials. Handles reCAPTCHA mitigation, "
            "brute-force account tracking thresholds, and multi-factor conditional logic. "
            "If 2FA is enabled, issues an active temporary pre-authentication state payload. "
            "Otherwise, updates explicit anti-CSRF infrastructure and maps active session tokens."
        ),
        request=LoginRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=PolymorphicProxySerializer(
                    component_name="LoginResponse",
                    serializers=[OTPResponseSerializer, SessionResponseSerializer],
                    resource_type_field_name=None,
                ),
                description=(
                    "Success Branch Outcomes:\n"
                    "1. OTP Response (User has 2FA enabled)\n"
                    "2. Token Response (User has 2FA disabled)"
                ),
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA validation failed",
            ),
            status.HTTP_424_FAILED_DEPENDENCY: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Failed Dependency - OTP not sent",
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too Many Requests",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="OTP Success (2FA Enabled)",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "True",
                    "pre_auth_token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                },
            ),
            OpenApiExample(
                name="Token Success (2FA Disabled)",
                response_only=True,
                status_codes=["200"],
                value={
                    "sessionid": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-SESSIONID",
                    "session_token_expiry": "2026-06-17T12:34:56.789Z",
                    "user_id": 42,
                    "user_role": "Default",
                    "csrf_token": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-CSRFTOKEN",
                    "csrf_token_expiry": "2026-06-18T12:34:56.789Z",
                },
            ),
            OpenApiExample(
                name="Missing email or username",
                response_only=True,
                status_codes=["400"],
                value={
                    "errors": {"email_or_username": ["Email or username is required."]}
                },
            ),
            OpenApiExample(
                name="Missing Password",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"password": ["Password is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid Credentials",
                response_only=True,
                status_codes=["400"],
                value={"error": "Invalid credentials"},
            ),
            OpenApiExample(
                name="Account Warning Limit (Attempts 3 or 4)",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": (
                        "Invalid credentials. You have 2 more "
                        "attempt(s) before your account is deactivated."
                    )
                },
            ),
            OpenApiExample(
                name="Max Attempts Hit (Lockout)",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": (
                        "Invalid credentials. Your account has "
                        "been deactivated. Contact an admin."
                    )
                },
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Invalid"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "High risk transaction blocked. Score: 0.3"},
            ),
            OpenApiExample(
                name="Deactivated Account Check",
                response_only=True,
                status_codes=["403"],
                value={"error": "Account has been deactivated. Contact your admin"},
            ),
            OpenApiExample(
                name="Unverified Email Check",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": "Email is not verified. You must verify your email first"
                },
            ),
            OpenApiExample(
                name="OAuth Provider Mismatch",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": "This process cannot be used, as user is created using google"
                },
            ),
            OpenApiExample(
                name="OTP Internal Transmit Failure",
                response_only=True,
                status_codes=["424"],
                value={"error": "Something went wrong, could not send OTP. Try again"},
            ),
            OpenApiExample(
                name="Throttled Wait Penalty",
                response_only=True,
                status_codes=["429"],
                value={
                    "error": "Please wait 45 seconds before requesting another OTP."
                },
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0911, R0914
        """Post a request to login. Returns an OTP or SessionID to the registered email."""
        try:
            req_serializer = LoginRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=req_validated_data["recaptcha_token"],
                expected_action="login",
                recaptcha_version=req_validated_data["recaptcha_version"],
                user_ip_address=req_validated_data["user_ip"],
                user_agent=req_validated_data["user_agent"],
            )

            if not is_human:
                return Response(
                    {"error": message},
                    status=status.HTTP_403_FORBIDDEN,
                )

            user = authenticate(
                request=request,
                username=req_validated_data["email_or_username"],
                password=req_validated_data["password"],
            )

            valid_serializer = ValidUserSerializer(
                data={}, context={"user": user, "request": request}
            )

            valid_serializer.is_valid(raise_exception=True)

            validated_user = valid_serializer.validated_data["user"]

            if validated_user.is_two_fa:
                otp_success = create_otp(user.id)
                if not otp_success.get("success"):
                    return Response(
                        {
                            "error": "Something went wrong, could not send OTP. Try again"
                        },
                        status=status.HTTP_424_FAILED_DEPENDENCY,
                    )

                otp_res_serializer = OTPResponseSerializer(data=otp_success)

                otp_res_serializer.is_valid(raise_exception=True)

                hashed_user_key = generate_cache_key(validated_user.id)
                cache.delete(f"login_failures:{hashed_user_key}")

                return Response(otp_res_serializer.data, status=status.HTTP_200_OK)

            login(request, validated_user)
            sessionid = request.session.session_key
            session_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.SESSION_COOKIE_TTL)
                - timedelta(seconds=10)
            ).isoformat()

            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "sessionid": sessionid,
                "session_token_expiry": session_token_expiry,
                "user_id": validated_user.id,
                "user_role": get_user_role(validated_user),
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            token_res_serializer = SessionResponseSerializer(data=raw_data)

            token_res_serializer.is_valid(raise_exception=True)

            hashed_user_key = generate_cache_key(validated_user.id)
            cache.delete(f"login_failures:{hashed_user_key}")

            return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, (ValidationError, ForbiddenValidationError)):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
