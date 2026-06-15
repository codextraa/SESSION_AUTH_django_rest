from datetime import datetime, timedelta, timezone
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import get_user_model, authenticate
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample

from server.renderers import ViewRenderer
from server.utils.recaptcha import verify_recaptcha_token
from server.schema_serializers import (
    SuccessResponseSerializer,
    ErrorResponseSerializer,
)
from .validation_serializers import ValidUserSerializer
from .request_serializers import RecaptchaRequestSerializer, LoginRequestSerializer
from .response_serializers import CSRFTokenResponseSerializer, OTPSuccessResponse, SessionSuccessResponse


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
                datetime.now(timezone.utc) + timedelta(days=1) - timedelta(minutes=1)
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


    @extend_schema(
        summary="Login to get an OTP",
        description=(
            "Authenticates the user with email and password. "
            "If valid, an OTP is sent to the registered email."
        ),
        request=LoginRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Email sent"},
                        "otp": {"type": "boolean", "example": True},
                        "user_id": {"type": "integer", "example": 1},
                    },
                },
            ),
            400: OpenApiResponse(
                description="Bad Request - Various authentication errors",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Invalid credentials",
                                (
                                    "Invalid credentials. You have X more attempt(s) "
                                    "before your account is deactivated."
                                ),
                                (
                                    "Invalid credentials. Your account is deactivated."
                                    " Verify your email."
                                ),
                                (
                                    "Invalid credentials. Your account is deactivated."
                                    " Contact an admin."
                                ),
                                "Email and password are required",
                                (
                                    "This process cannot be used, "
                                    "as user is created using {auth_provider}"
                                ),
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Something went wrong, could not send OTP. Try again",
                            ],
                        }
                    },
                },
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "string",
                            "example": "Request was throttled. Expected available in n seconds.",
                        }
                    },
                },
            ),
            500: OpenApiResponse(
                description="Internal Server Error",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Internal Server Error"}
                    },
                },
            ),
        },
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0911
        """Post a request to login. Returns an OTP or seesion id to the registered email."""
        try:
            req_serializer = LoginRequestSerializer(
                data=request.data,
                context={"request": request},
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
                return Response({"error": message}, status=status.HTTP_403_FORBIDDEN)

            user = authenticate(
                request=request,
                username=req_validated_data["email_or_username"],
                password=req_validated_data["password"],
            )

            valid_serializer = ValidUserSerializer(
                data={},
                context={"user": user},
            )
            valid_serializer.is_valid(raise_exception=True)

            validated_user = valid_serializer.validated_data["user"]

            if validated_user.is_two_fa:
                pass
            else:
                pass
            
            # email = request.data.get("email")
            # password = request.data.get("password")

            # if not email or not password:
            #     return Response(
            #         {"error": "Email and password are required"},
            #         status=status.HTTP_400_BAD_REQUEST,
            #     )

            # user = check_user_validity(email)

            # if isinstance(user, Response):
            #     return user

            # # Check if password is correct
            # if not user.check_password(password):
            #     # Increment failed login attempts
            #     if now() - user.last_failed_login_time <= timedelta(minutes=10):
            #         user.failed_login_attempts += 1
            #     else:
            #         user.failed_login_attempts = 1

            #     user.last_failed_login_time = now()
            #     user.save()

            #     if user.failed_login_attempts == settings.MAX_LOGIN_FAILURE_LIMIT:
            #         # Lock account
            #         if user.is_superuser:
            #             user.is_email_verified = False
            #             user.save()
            #             return Response(
            #                 {
            #                     "error": (
            #                         "Invalid credentials. Your account is deactivated. "
            #                         "Verify your email."
            #                     )
            #                 },
            #                 status=status.HTTP_400_BAD_REQUEST,
            #             )
            #         user.is_active = False
            #         user.save()
            #         return Response(
            #             {
            #                 "error": (
            #                     "Invalid credentials. Your account is deactivated. "
            #                     "Contact an admin."
            #                 )
            #             },
            #             status=status.HTTP_400_BAD_REQUEST,
            #         )

            #     if user.failed_login_attempts >= 3:
            #         remaining_attempts = (
            #             settings.MAX_LOGIN_FAILURE_LIMIT - user.failed_login_attempts
            #         )
            #         return Response(
            #             {
            #                 "error": (
            #                     f"Invalid credentials. You have {remaining_attempts} "
            #                     "more attempt(s) before your account is deactivated."
            #                 )
            #             },
            #             status=status.HTTP_400_BAD_REQUEST,
            #         )

            #     return Response(
            #         {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            #     )

            # # Reset failed login attempts
            # if user.failed_login_attempts > 0:
            #     user.failed_login_attempts = 0
            #     user.save()

            # # Generate OTP
            # response = create_otp(user.id, email, password)

            # return response

        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )