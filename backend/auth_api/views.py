"""Views for Auth API."""
import requests, json
from datetime import datetime, timezone, timedelta
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authentication import SessionAuthentication
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.utils.timezone import now
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from social_django.utils import load_backend, load_strategy
from social_core.exceptions import AuthException
from .renderers import ViewRenderer
from .paginations import UserPagination
from .filters import UserFilter
from .utils import (
    EmailOtp,
    EmailLink,
    PhoneOtp
)
from .serializers import (
    UserSerializer,
    UserImageSerializer,
    UserListSerializer,
    UserActionSerializer,
    RecaptchaSerializer,
    LoginSerializer,
    ResendOtpSerializer,
    SessionSerializer,
    PhoneVerificationSerializer,
    PasswordResetSerializer,
    VerificationThroughEmailSerializer,
    InputPasswordResetSerializer,
    CreateUserSerializer,
    UpdateUserSerializer,
    SocialOAuthSerializer
)


def check_token_validity(request):
    """Check if token is valid."""
    token = request.query_params.get('token')
    expiry = request.query_params.get('expiry')
    
    if not token or not expiry:
        return Response({"error": "Missing verification link."}, status=status.HTTP_400_BAD_REQUEST)
    
    expiry_time = datetime.fromtimestamp(int(expiry), tz=timezone.utc)
    
    if datetime.now(timezone.utc) > expiry_time:
        return Response({"error": "The verification link has expired."}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        email = EmailLink.verify_link(token)
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    return email
    
def check_user_validity(email):
    """Check if user is valid using email."""
    user = get_user_model().objects.filter(email=email).first()
        
    # Check if user exists
    if not user:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    
    if user.auth_provider != 'email':
        return Response({"error": f"This process cannot be used, as user is created using {user.auth_provider}"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if user is email verified
    if not user.is_email_verified:
        return Response({"error": "Email is not verified. You must verify your email first"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if user is active
    if not user.is_active:
        return Response({"error": "Account is deactivated. Contact your admin"}, status=status.HTTP_400_BAD_REQUEST)
        
    return user

def get_user_role(user):
    """Get user role."""
    user_groups = user.groups.all()
    
    if user_groups.filter(name='Default').exists():
        user_role = 'Default'
    elif user_groups.filter(name='Admin').exists():
        user_role = 'Admin'
    elif user_groups.filter(name='Superuser').exists():
        user_role = 'Superuser'
    else:
        user_role = 'UnAuthorized'
        
    return user_role

def check_user_id(user_id):
    """Check if user id is valid."""
    if not user_id:
        return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user_id = int(user_id)
    except Exception as e:
        # print(e)
        return Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST)
    
    user = get_user_model().objects.filter(id=user_id).first()
    
    if not user:
        return Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST)
    
    return check_user_validity(user.email)

def create_otp(user_id, email, password):
    """Generate a 6 digit OTP and send it to the user's email."""
    otp = EmailOtp.generate_otp()
    otp_email = EmailOtp.send_email_otp(email, otp)
    
    # Check if the email was sent
    if otp_email:
        # Setting the cache data
        cache.set(f"id_{user_id}", user_id, timeout=60) # Cache id for 1 minute (used for email verification)
        cache.set(f"otp_{user_id}", otp, timeout=600) # Cache otp for 1 minute (used for otp verification)
        cache.set(f"email_{user_id}", email, timeout=600) # Cache email for 10 minutes (used for otp verification)
        cache.set(f"password_{user_id}", password, timeout=600)  # Store password in cache for verification
        return Response({"success": "Email sent", "otp": True, "user_id": user_id}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "Something went wrong, could not send OTP. Try again", "otp": False}, status=status.HTTP_400_BAD_REQUEST)

def check_throttle_duration(self, request):
    """
    Check duration for throttling
    """
    throttle_durations = []
    for throttle in self.get_throttles():
        if not throttle.allow_request(request, self):
            throttle_durations.append(throttle.wait())
            
    return throttle_durations

def start_throttle(self, throttle_durations, request):
    # Filter out `None` values which may happen in case of config / rate
    # changes, see #1438
    durations = [
        duration for duration in throttle_durations
        if duration is not None
    ]

    duration = max(durations, default=None)
    self.throttled(request, duration)
    
class CSRFTokenView(APIView):
    """CSRF Token View."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    
    @extend_schema(
        summary="Get CSRF Token",
        description="Returns a CSRF token along with its expiration time.",
        responses={
            200: OpenApiResponse(
                description="CSRF token returned",
                response={
                    "type": "object",
                    "properties": {
                        "csrf_token": {"type": "string", "example": "csrf_token"},
                        "csrf_token_expiry": {"type": "string", "example": "2023-01-01T00:00:00Z"}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Bad Request - Invalid parameters",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Invalid request parameters"}
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
        }
    )
    def get(self, request, *args, **kwargs):
        """Get Method for CSRF Token."""
        try:
            csrf_token = get_token(request)
            # Substracting a minute so that frontend request doesn't give token expired error
            csrf_token_expiry = datetime.now(timezone.utc) + timedelta(days=1) - timedelta(minutes=1)
            return Response(
                {"csrf_token": csrf_token, "csrf_token_expiry": csrf_token_expiry.isoformat()},
                status=status.HTTP_200_OK
            )
        except Exception as e:
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
        request=RecaptchaSerializer,
        responses={
            200: OpenApiResponse(
                description="reCAPTCHA validation successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "reCAPTCHA validation successful."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Bad Request - Invalid reCAPTCHA token or JSON",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Invalid reCAPTCHA token."}
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
        }
    )
    def post(self, request, *args, **kwargs):
        """Post a request to validate reCAPTCHA. Returns a response with success or error message."""
        try:
            recaptcha_token = request.data.get('recaptcha_token')
            
            recaptcha_response = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': settings.RECAPTCHA_SECRET_KEY,
                    'response': recaptcha_token
                }
            )
            result = recaptcha_response.json()
            
            if result.get('success'):
                return Response({'success': 'reCAPTCHA validation successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid reCAPTCHA token.'}, status=status.HTTP_400_BAD_REQUEST)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    """Login View."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        user = get_user_model().objects.filter(email=request.data.get('email')).first()
        
        if user:
            cached_id = cache.get(f"id_{user.id}")
        else:
            cached_id = None

        if throttle_durations and cached_id:
            start_throttle(self, throttle_durations, request)

    @extend_schema(
        summary="Login to get an OTP",
        description="Authenticates the user with email and password. If valid, an OTP is sent to the registered email.",
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Email sent"},
                        "otp": {"type": "boolean", "example": True},
                        "user_id": {"type": "integer", "example": 1}
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
                                "Invalid credentials. You have X more attempt(s) before your account is deactivated.",
                                "Invalid credentials. Your account is deactivated. Verify your email.",
                                "Invalid credentials. Your account is deactivated. Contact an admin.",
                                "Email and password are required",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Something went wrong, could not send OTP. Try again"
                            ]
                        }
                    },
                },
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
    def post(self, request, *args, **kwargs):
        """Post a request to login. Returns an OTP to the registered email."""
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            
            if not email or not password:
                return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)
            
            user = check_user_validity(email)
            
            if isinstance(user, Response):
                return user
            
            # Check if password is correct
            if not user.check_password(password):
                # Increment failed login attempts
                if now() - user.last_failed_login_time <= timedelta(minutes=10):
                    user.failed_login_attempts += 1
                else:
                    user.failed_login_attempts = 1
                    
                user.last_failed_login_time = now()
                user.save()
                
                if user.failed_login_attempts == settings.MAX_LOGIN_FAILURE_LIMIT:
                    # Lock account
                    if user.is_superuser:
                        user.is_email_verified = False
                        user.save()
                        return Response({
                            "error": "Invalid credentials. Your account is deactivated. Verify your email."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        user.is_active = False
                        user.save()
                        return Response({
                            "error": "Invalid credentials. Your account is deactivated. Contact an admin."
                        }, status=status.HTTP_400_BAD_REQUEST)
                
                if user.failed_login_attempts >= 3:
                    remaining_attempts = settings.MAX_LOGIN_FAILURE_LIMIT - user.failed_login_attempts
                    return Response({
                        "error": f"Invalid credentials. You have {remaining_attempts} more attempt(s) before your account is deactivated."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                
                return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Reset failed login attempts
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save()
            
            # Generate OTP
            response = create_otp(user.id, email, password)
            
            return response
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class ResendOtpView(APIView):
    """Resend OTP View."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_id = cache.get(f"id_{request.data.get('user_id')}")

        if throttle_durations and cached_id:
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        summary="Resend OTP",
        description="If the session is valid and the user exists, an OTP is resent to the registered email address.",
        request=ResendOtpSerializer,
        responses={
            200: OpenApiResponse(
                description="Email sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Email sent"},
                        "otp": {"type": "boolean", "example": True},
                        "user_id": {"type": "integer", "example": 1}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Bad Request - Various errors related to invalid session, user details, etc.",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Session expired. Please login again.",
                                "Invalid Session",
                                "Invalid credentials",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Something went wrong, could not send OTP. Try again"
                            ]
                        }
                    }
                }
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
    def post(self, request, *args, **kwargs):
        """Post a request to resend OTP. Returns an OTP to the registered email."""
        try:
            user_id = request.data.get('user_id')
            
            user = check_user_id(user_id)
            
            if isinstance(user, Response):
                return user
            
            email = cache.get(f"email_{user.id}")
            password = cache.get(f"password_{user.id}")
            
            if not email or not password:
                return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate OTP
            response = create_otp(user.id, email, password)
            
            return response
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SessionView(APIView):
    """Token Generation View after OTP verification."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Generate Session",
        description="Verifies OTP and generates Session ID and new CSRFToken for the authenticated user.",
        request=SessionSerializer,
        responses={
            200: OpenApiResponse(
                description="Session response",
                response={
                    "type": "object",
                    "properties": {
                        "sessionid": {"type": "string", "example": "sessionid"},
                        "user_id": {"type": "integer", "example": 1},
                        "user_role": {"type": "string", "example": "Admin"},
                        "csrf_token": {"type": "string", "example": "csrf_token"},
                        "csrf_token_expiry": {"type": "string", "example": "2023-01-01T00:00:00Z"}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Bad Request - Various errors related to OTP verification or session issues",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Invalid OTP",
                                "Session expired. Please login again.",
                                "Invalid credentials",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Invalid Session"
                            ],
                        },
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
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to TokenView. Verifies OTP and generates JWT tokens."""
        try:
            user_id = request.data.pop("user_id", None)
            otp_from_request = request.data.pop("otp", None)
            
            user = check_user_id(user_id)
            
            if isinstance(user, Response):
                return user
            
            # Get email and password from the cache
            email = cache.get(f"email_{user.id}")
            password = cache.get(f"password_{user.id}")

            if not email or not password:
                return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify OTP
            otp_verify = EmailOtp.verify_otp(user.id, otp_from_request)
            
            if not otp_verify:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate session ID
            user = authenticate(request, email=email, password=password)
            
            login(request, user)
            
            sessionid = request.session.session_key
            csrf_token = get_token(request)
            # Substracting a minute so that frontend request doesn't give token expired error
            csrf_token_expiry = datetime.now(timezone.utc) + timedelta(days=1) - timedelta(minutes=1)
            user_role = get_user_role(user)

            return Response({
                "sessionid": sessionid,
                "user_id": user.id,
                "user_role": user_role, 
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry.isoformat()           
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
class EmailVerifyView(APIView):
    """Email Verify View."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "email_verify"
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        summary="Verify user's email address",
        description="This endpoint verifies the user's email address using a token and expiry time sent during registration.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for email verification, sent to the user's email.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the verification link (in seconds since the epoch).",
                required=True,
                type=int,
                location=OpenApiParameter.QUERY,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Email verification successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "string",
                            "example": "Email verified successfully",
                        }
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid or expired token or user not found",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Missing verification link.",
                                "The verification link has expired.",
                                "Invalid verification link",
                                "Invalid credentials",
                            ],
                        }
                    },
                },
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        """Get the link and check it's validity"""
        try:
            email = check_token_validity(request)

            if isinstance(email, Response):
                return email
            
            user = get_user_model().objects.filter(email=email).first()
            
            # Check if user exists
            if not user:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            
            user.is_active = True
            user.is_email_verified = True
            user.save()
            
            return Response({"success": "Email verified successfully"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Send an email verification link",
        description="This endpoint sends an email verification link to the user's email address.",
        request=VerificationThroughEmailSerializer, 
        responses={
            200: OpenApiResponse(
                description="Verification link sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "string",
                            "example": "Verification link sent. Please verify your email to activate your account.",
                        }
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid email address or user not found",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Invalid credentials",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email already verified",
                                "Failed to send email verification link.",
                                "Verification link sent. Please verify your email to activate your account.",
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
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
    def post(self, request, *args, **kwargs):
        """Post a request to Email Verify View. Email verification link is sent to the user's email."""
        try: 
            email = request.data.get("email")
            
            user = get_user_model().objects.filter(email=email).first()

            # Check if user exists
            if not user:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.auth_provider != 'email':
                return Response({"error": f"This process cannot be used, as user is created using {user.auth_provider}"}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.is_email_verified:
                return Response({"error": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)
            
            email_sent = EmailLink.send_email_link(email)
            
            if not email_sent:
                return Response(
                    {"error": "Failed to send email verification link."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            cache.set(f"email_{email}", email, timeout=60) # Cache email for 10 minutes
            
            return Response(
                {"success": "Verification link sent. Please verify your email to activate your account."},
                status=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class PhoneVerifyView(APIView):
    """Phone Verification View."""
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'phone_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)

        if throttle_durations and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        summary="Send OTP to Phone",
        description="This endpoint sends an OTP to the user's phone number.",
        request=None,
        responses={
            200: OpenApiResponse(
                description="OTP sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "OTP sent successfully"},
                    },
                },
            ),
            400: OpenApiResponse(
                description="Failed to send OTP",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Something went wrong, could not send OTP. Try again",
                                "Invalid phone number",
                            ]
                        }
                    },
                },
            ),
            403: OpenApiResponse(
                description="Forbidden",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Authentication credentials were not provided."}
                    },
                },
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
    def post(self, request, *args, **kwargs):
        """Post a request to Phone Verify View. OTP is sent to the user's phone number."""
        try:
            user = request.user
            email = user.email
            phone = user.phone_number
            
            otp_sent = PhoneOtp.send_otp(email, str(phone))
            
            if otp_sent:
                return Response({"success": "OTP sent successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Something went wrong, could not send OTP. Try again"}, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Phone Verification",
        description="This endpoint verifies the user's phone number using an OTP.",
        request=PhoneVerificationSerializer,  # Use the PhoneVerificationSerializer for OTP input
        responses={
            200: OpenApiResponse(
                description="Phone verified successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Phone verified successfully"},
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid OTP",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "OTP is required",
                                "Invalid OTP",
                            ]
                        }
                    },
                },
            ),
            403: OpenApiResponse(
                description="Forbidden",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Authentication credentials were not provided."}
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
    def patch(self, request, *args, **kwargs):
        """Patch a request to Phone Verify View. OTP is sent to the user's phone number."""
        try:
            otp = request.data.get("otp")
            
            if not otp:
                return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

            user = request.user
            phone_number = user.phone_number
            
            otp_verified = PhoneOtp.verify_otp(phone_number, otp)
            
            if otp_verified:
                user.is_phone_verified = True
                user.save()
                return Response({"success": "Phone verified successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class PasswordResetView(APIView):
    """Password Reset View."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'password_reset'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        summary="Verify Password Reset Link",
        description="Verify the token and expiry provided in the query parameters to validate the password reset link.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for password reset verification.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the password reset link.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Password reset link verified successfully.",
                response={
                    "type": "object", 
                    "properties": {
                        "success": {"type": "string", "example": "Password verification link ok"}
                    }
                },
            ),
            400: OpenApiResponse(
                description="Invalid or expired password reset link.",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Missing verification link.",
                                "The verification link has expired.",
                                "The verification link has expired.",
                                "Invalid verification link."
                            ]
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
    def get(self, request, *args, **kwargs):
        """Get and validate the password reset link."""
        try:
            email = check_token_validity(request)
            
            if isinstance(email, Response):
                return email
            
            return Response({"success": "Password verification link ok"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    @extend_schema(
        summary="Send Password Reset Link",
        description="Send a password reset link to the user's email address if it is verified and active.",
        request=VerificationThroughEmailSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset link sent successfully.",
                response={
                    "type": "object", 
                    "properties": {
                        "success": {"type": "string", "example": "Password reset link sent. Please check your email to reset your password."}
                    }
                },
            ),
            400: OpenApiResponse(
                description="User not found or email not verified.",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Invalid credentials",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Failed to send password reset link."
                            ]
                        }
                    },
                },
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
    def post(self, request, *args, **kwargs):
        """Post a request to Password Reset View. Password reset link is sent to the user's email address."""
        try:
            email = request.data.get('email')
            
            user = check_user_validity(email)
            
            if isinstance(user, Response):
                return user
            
            email_sent = EmailLink.send_password_reset_link(user.email)
            
            if not email_sent:
                return Response(
                    {"error": "Failed to send password reset link."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            cache.set(f"email_{user.email}", user.email, timeout=60) # Cache email for 10 minutes
            
            return Response(
                {"success": "Password reset link sent. Please check your email to reset your password."},
                status=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Reset Password",
        description="Reset the user's password using the provided token, expiry, and new password. Both passwords must match.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for password reset verification.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the password reset link.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
        ],
        request=InputPasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset successful.",
                response={
                    "type": "object", 
                    "properties": {
                        "success": {"type": "string", "example": "Password reset successful"}
                    }
                },
            ),
            400: OpenApiResponse(
                description="Invalid or mismatched passwords, or user not valid.",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Missing verification link.",
                                "The verification link has expired.",
                                "Invalid credentials",
                                "This process cannot be used, as user is created using {auth_provider}",
                                "Email is not verified. You must verify your email first",
                                "Account is deactivated. Contact your admin",
                                "Failed to send password reset link.",
                                "Password is required.",
                                "Passwords do not match",
                                "New password cannot be the same as the old password.",
                                {
                                    "short": "Password must be at least 8 characters long.",
                                    "lower": "Password must contain at least one lowercase letter.",
                                    "upper": "Password must contain at least one uppercase letter.",
                                    "number": "Password must contain at least one number.",
                                    "special": "Password must contain at least one special character."
                                }
                            ]
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
    def patch(self, request, *args, **kwargs):
        """Patch a request to Password Reset View. Password is reset using the provided token, expiry, and new password."""
        email = check_token_validity(request)

        if isinstance(email, Response):
            return email
        
        user = check_user_validity(email)
        
        if isinstance(user, Response):
            return user
        
        password = request.data.get('password')
        c_password = request.data.get('c_password')
        
        if password != c_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        # password reset serializer
        serializer = PasswordResetSerializer(instance=user, data={"password": password})
        
        if not serializer.is_valid():
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        
        return Response({"success": "Password reset successful."}, status=status.HTTP_200_OK)
        
class UserViewSet(ModelViewSet):
    """Viewset for User APIs."""
    queryset = get_user_model().objects.all() # get all the users
    serializer_class = UserSerializer # User Serializer initialized
    authentication_classes = [SessionAuthentication] # Using session auth
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_verify'
    renderer_classes = [ViewRenderer]
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserFilter
    pagination_class = UserPagination
    http_method_names = ['get', 'post', 'patch', 'delete']

    def get_permissions(self):
        """Permission for CRUD operations."""
        if self.action == 'create': # No permission while creating user
            permission_classes = [AllowAny]
        elif self.action == 'deactivate_user': # Only Admins are allowed
            permission_classes = [IsAuthenticated]
        elif (self.action == 'activate_user' or self.action == 'delete'): # Only Admins are allowed
            permission_classes = [IsAuthenticated, IsAdminUser]
        else: # RUD operations need permissions
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        """Return the serializer class for the action."""
        if self.action == "list": # List of users handled with different serializer
            return UserListSerializer
        if self.action == "deactivate_user" or self.action == "activate_user": # Deactivation handled with different serializer
            return UserActionSerializer
        if self.action == "upload_image": # Image handled with different serializer
            return UserImageSerializer
        return super().get_serializer_class()
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
            
    def http_method_not_allowed(self, request, *args, **kwargs):
        """Disallow PUT operation."""
        if request.method == 'PUT':
            return Response(
                {"error": "PUT operation not allowed."}, 
                status=status.HTTP_405_METHOD_NOT_ALLOWED
            )
            
    @extend_schema(
        summary="Get All Users List",
        description="List of all users using Pagination and Filters.",
        responses={
            200: UserListSerializer,
            400: OpenApiResponse(
                description="Bad Request - Invalid parameters",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Invalid request parameters"}
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
        }
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, args, kwargs)
    
    @extend_schema(
        summary="Get Single User",
        description="Get everything of a single user by ID.",
        responses={
            200: UserSerializer,
            400: OpenApiResponse(
                description="Bad Request - Invalid parameters",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Invalid request parameters"}
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
        }
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(
        summary="Create User",
        description="Create a new user or admin(only superuser can create).",
        request=CreateUserSerializer,
        responses={
            200: OpenApiResponse(
                description="Creation successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "string", 
                            "example": "User created successfully. Please verify your email to activate your account."
                        }
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Please confirm your password.",
                                "Passwords do not match",
                                "Failed to send email verification link.",
                                {
                                    "email": [
                                        "user with this email already exists.",
                                        "Enter a valid email address.",
                                    ],
                                    "username": [
                                        "user with this username already exists.",
                                        "Username must be at least 6 characters long.",
                                    ],
                                    "phone_number": [
                                        "The phone number entered is not valid."
                                    ],
                                    "password": {
                                        "short": "Password must be at least 8 characters long.",
                                        "lower": "Password must contain at least one lowercase letter.",
                                        "upper": "Password must contain at least one uppercase letter.",
                                        "number": "Password must contain at least one number.",
                                        "special": "Password must contain at least one special character."
                                    }
                                },
                            ]
                        }
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "You do not have permission to create a superuser. Contact Developer.",
                                "You do not have permission to create an admin user.",
                                "Profile Image cannot be updated here. Use the Upload Image Action.",
                                "Forbidden fields cannot be updated."
                            ]
                        }
                    },
                },
            ),
            429: OpenApiResponse(
                description="Too Many Requests - Rate limit exceeded",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Request was throttled. Expected available in n seconds."}
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
        }
    )
    @method_decorator(csrf_protect)
    def create(self, request, *args, **kwargs):
        """Create new user and send email verification link."""
        current_user = self.request.user
        
        if ('is_superuser' in request.data):
            return Response(
                {"error": "You do not have permission to create a superuser. Contact Developer."},
                status=status.HTTP_403_FORBIDDEN,
            )
        
        if ('is_staff' in request.data and not current_user.is_superuser):
            return Response(
                {"error": "You do not have permission to create an admin user."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        if 'profile_img' in request.data:
            return Response(
                {"error": "Profile Image cannot be updated here. Use the Upload Image Action."},
                status=status.HTTP_403_FORBIDDEN
            )

        if ('slug' in request.data or
            'is_email_verified' in request.data or
            'is_phone_verified' in request.data or
            'is_active' in request.data):
            return Response(
                {"error": "Forbidden fields cannot be updated."},
                status=status.HTTP_403_FORBIDDEN
            )
            
        password = request.data.get('password')
        if not request.data.get('c_password'):
            return Response({"error": "Please confirm your password."}, status=status.HTTP_400_BAD_REQUEST)
            
        c_password = request.data.pop('c_password')
        if password != c_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
            
        request.data['is_active'] = False
        response = super().create(request, *args, **kwargs)
        
        if response.status_code != status.HTTP_201_CREATED:
            return response
        
        # Send email verification link
        user = get_user_model().objects.get(email=response.data["email"])
        email_sent = EmailLink.send_email_link(user.email)
        
        if not email_sent:
            return Response(
                {"error": "Failed to send email verification link."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        cache.set(f"email_{user.email}", user.email, timeout=60) # Cache email for 10 minutes
        
        return Response(
            {"success": "User created successfully. Please verify your email to activate your account."},
            status=status.HTTP_201_CREATED
        )
        
    @extend_schema(
        summary="Update User (Not Allowed)",
        description="Update everything of an user (Method Not Allowed)",
        request=UpdateUserSerializer,
        responses={
            405: OpenApiResponse(
                description="Method Not Allowed",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "PUT operation not allowed."}
                    },
                },
            ),
        }
    )
    @method_decorator(csrf_protect)
    def update(self, request, *args, **kwargs):
        """Allow only users to update their own profile. SuperUser can update any profile.
        Patch method allowed, Put method not allowed"""
        method = self.http_method_not_allowed(request)
        
        if method:
            return method
        
        current_user = self.request.user
        user = self.get_object()
        
        if 'email' in request.data:
            return Response(
                {"error": "You cannot update the email field."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if ('password' in request.data or 'c_password' in request.data):
            return Response(
                {"error": "Password reset cannot be done without verification link."},
                status=status.HTTP_403_FORBIDDEN
            )
            
        if 'profile_img' in request.data:
            return Response(
                {"error": "Profile Image cannot be updated here. Use the Upload Image Action."},
                status=status.HTTP_403_FORBIDDEN
            )

        if ('slug' in request.data or
            'is_email_verified' in request.data or
            'is_phone_verified' in request.data or
            'is_active' in request.data or 
            'is_staff' in request.data  or
            'is_superuser' in request.data):
            return Response(
                {"error": "Forbidden fields cannot be updated."},
                status=status.HTTP_403_FORBIDDEN
            )

        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to update this user."},
                status=status.HTTP_403_FORBIDDEN,
            )

        response = super().update(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_200_OK:
            return Response({"success": "User profile updated successfully."}, status=status.HTTP_200_OK)
        
        return response

    @extend_schema(
        summary="Update User",
        description="Update an existing user's profile",
        request=UpdateUserSerializer,
        responses={
            200: OpenApiResponse(
                description="Update successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "User profile updated successfully."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                {
                                    "username": [
                                        "user with this username already exists.",
                                        "Username must be at least 6 characters long.",
                                    ],
                                    "phone_number": [
                                        "The phone number entered is not valid."
                                    ]
                                }
                            ]
                        }
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "You cannot update the email field.",
                                "Password reset cannot be done without verification link.",
                                "Profile Image cannot be updated here. Use the Upload Image Action.",
                                "Forbidden fields cannot be updated.",
                                "You do not have permission to update this user."
                            ]
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
        }
    )
    def partial_update(self, request, *args, **kwargs):
        """Patch Method for updating user profile"""
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        summary="Delete User",
        description="Delete a deactivated user",
        responses={
            200: OpenApiResponse(
                description="Deletion successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "User example.com deleted successfully."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "string", 
                            "example": "You must deactivate the user before deleting it."
                        }
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Only superusers can delete users.",
                                "You cannot delete superusers"
                            ]
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
        }
    )
    @method_decorator(csrf_protect)
    def destroy(self, request, *args, **kwargs):
        """Allow only superusers to delete normal or staff users and clean up profile image."""
        current_user = self.request.user
        user_to_delete = self.get_object()

        if not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can delete users."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        if user_to_delete.is_superuser:
            return Response(
                {"error": "You cannot delete superusers"},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        if user_to_delete.is_active:
            return Response(
                {"error": "You must deactivate the user before deleting it."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check and delete the profile image if it's not the default image
        default_image_path = 'profile_images/default_profile.jpg'
        if user_to_delete.profile_img and user_to_delete.profile_img.name != default_image_path:
            user_to_delete.profile_img.delete(save=False)

        email = user_to_delete.email
        response = super().destroy(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_204_NO_CONTENT:
            return Response({"success": f"User {email} deleted successfully."}, status=status.HTTP_200_OK)
        
        return response

    @extend_schema(
        summary="Upload Profile Image",
        description="Upload an image for the user's profile",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "profile_img": {
                        "type": "string",
                        "format": "binary",
                        "description": "The image file to upload"
                    }
                }
            }
        },
        responses={
            200: OpenApiResponse(
                description="Image uploaded",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Image uploaded successfully."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "No profile image provided.",
                                {
                                    "profile_img": [
                                        'Profile image is required.',
                                        {
                                            "size": 'Profile image size should not exceed 2MB.',
                                            "type": 'Profile image type should be JPEG, PNG'
                                        },
                                    ],
                                },
                            ],
                        },
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "string", 
                            "example": "You do not have permission to upload an image for this user."
                        },
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
        }
    )
    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='upload-image', parser_classes=[MultiPartParser, FormParser])  # detail=True is only for a single user
    def upload_image(self, request, pk=None):
        """Update user profile image"""
        user = self.get_object()  # get the user
        current_user = self.request.user  # Get the user making the request
        
        if not request.data:
            return Response({"error": "No profile image provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the request is made by the user themselves or a superuser
        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to upload an image for this user."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        default_image_path = 'profile_images/default_profile.jpg'  # Define the default image path

        # Check if the user has an existing image that is not the default image
        if user.profile_img and user.profile_img.name != default_image_path:
            # Remove the previous image file
            user.profile_img.delete(save=False)
        
        serializer = self.get_serializer(
            user,
            data=request.data,
            partial=True  # Only updating profile_img
        )
        serializer.is_valid(raise_exception=True)  # returns 400 if fails
        serializer.save()

        return Response({"success": "Image uploaded successfully."}, status=status.HTTP_200_OK)
        
    @extend_schema(
        summary="Deactivate User",
        description="Deactivate an activated user",
        responses={
            200: OpenApiResponse(
                description="Deactivation successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "User example.com has been deactivated."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "User is already deactivated."}
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "You do not have permission to deactivate users.",
                                "You cannot deactivate yourself as a superuser.",
                                "You cannot deactivate yourself as a staff. Contact a superuser",
                                "Only superusers can deactivate staff users.",
                                "You cannot deactivate a superuser."
                            ]
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
        }
    )
    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='deactivate-user')
    def deactivate_user(self, request, pk=None):
        """Deactivate a user (only staff and superuser can do to other users)"""
        try:
            user_to_deactivate = self.get_object()
            current_user = self.request.user

            if not user_to_deactivate.is_active:
                return Response(
                    {"error": "User is already deactivated."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not (current_user.is_superuser or current_user.is_staff):
                if user_to_deactivate != current_user:
                    return Response(
                        {"error": "You do not have permission to deactivate users."},
                        status=status.HTTP_403_FORBIDDEN
                    )

            if user_to_deactivate == current_user and current_user.is_staff:
                if current_user.is_superuser:
                    detail = "You cannot deactivate yourself as a superuser."
                else:
                    detail = "You cannot deactivate yourself as a staff. Contact a superuser"

                return Response(
                    {"error": detail},
                    status=status.HTTP_403_FORBIDDEN
                )

            if user_to_deactivate.is_staff and not current_user.is_superuser:
                return Response(
                    {"error": "Only superusers can deactivate staff users."},
                    status=status.HTTP_403_FORBIDDEN
                )

            if user_to_deactivate.is_superuser:
                return Response(
                    {"error": "You cannot deactivate a superuser."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            user_to_deactivate.is_active = False
            user_to_deactivate.save()

            return Response(
                {"success": f"User {user_to_deactivate.email} has been deactivated."},
                status=status.HTTP_200_OK,
            )
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR,)

    @extend_schema(
        summary="Activate User",
        description="Activate a deactivated user",
        responses={
            200: OpenApiResponse(
                description="Activation successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "User example.com has been reactivated."}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "User is already deactivated."}
                    },
                },
            ),
            403: OpenApiResponse(
                description="Permission Denied",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "You do not have permission to activate users.",
                                "You cannot activate yourself.",
                                "Only superusers can activate staff users.",
                            ]
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
        }
    )
    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='activate-user')
    def activate_user(self, request, pk=None):
        """Activate a user (only staff and superuser can do this)"""
        try:
            user_to_activate = self.get_object()
            current_user = self.request.user

            if user_to_activate.is_active:
                return Response(
                    {"error": "User is not deactivated."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not (current_user.is_superuser or current_user.is_staff):
                return Response(
                    {"error": "You do not have permission to activate users."},
                    status=status.HTTP_403_FORBIDDEN
                )

            if user_to_activate == current_user:
                return Response(
                    {"error": "You cannot activate yourself."},
                    status=status.HTTP_403_FORBIDDEN
                )

            if user_to_activate.is_staff and not current_user.is_superuser:
                return Response(
                    {"error": "Only superusers can activate staff users."},
                    status=status.HTTP_403_FORBIDDEN
                )

            user_to_activate.is_active = True
            user_to_activate.save()

            return Response(
                {"success": f"User {user_to_activate.email} has been reactivated."},
                status=status.HTTP_200_OK,
            )
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Logout",
        description="Logout by deleting the sessionID from cache and db",
        request=None,
        responses={
            200: OpenApiResponse(
                description="Logout successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Logged out successfully"}
                    }
                }
            ),
            400: OpenApiResponse(
                description="Bad Request - Invalid parameters",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {"type": "string", "example": "Invalid request parameters"}
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
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        try:
            # Extract tokens from the request
            session_key = request.session.session_key
            
            logout(request)
            
            # Remove session_key and data from cache and db
            if session_key:
                cache.delete(f"django.contrib.sessions.cached_db{session_key}")
                Session.objects.filter(session_key=session_key).delete()
                
            return Response({"success": "Logged out successfully"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class SocialAuthView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Social Login",
        description="Login using social media accounts. (Google, Facebook, GitHub)",
        request=SocialOAuthSerializer,
        responses={
            200: OpenApiResponse(
                description="Session response",
                response={
                    "type": "object",
                    "properties": {
                        "sessionid": {"type": "string", "example": "sessionid"},
                        "user_id": {"type": "integer", "example": 1},
                        "user_role": {"type": "string", "example": "Admin"},
                        "csrf_token": {"type": "string", "example": "csrf_token"},
                        "csrf_token_expiry": {"type": "string", "example": "2023-01-01T00:00:00Z"}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "errors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": [
                                "Token and provider are required",
                                "Account is deactivated. Contact your admin.",
                                "Authentication failed, user not found",
                                "User with this email already created using password. Please login using password.",
                                "User with this email already created using {auth_provider}. Please login using {auth_provider}."
                            ]
                        }
                    }
                }
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
        }
    )
    def post(self, request, *args, **kwargs):
        token = request.data.get("token")
        provider = request.data.get("provider")
        if not token or not provider:
            return Response({"error": "Token and provider are required"}, status=400)

        try:
            # Load social auth backend dynamically
            strategy = load_strategy(request)
            backend = load_backend(strategy, provider, redirect_uri=None)
            user = backend.do_auth(token)
            
            if isinstance(user, Response):
                return user
            
            if user:
                if not user.is_active:
                    return Response({"error": "Account is deactivated. Contact your admin."}, status=400)
                # Generate session for user
                login(request, user)
                
                sessionid = request.session.session_key
                csrf_token = get_token(request)
                # Substracting a minute so that frontend request doesn't give token expired error
                csrf_token_expiry = datetime.now(timezone.utc) + timedelta(days=1) - timedelta(minutes=1)
                user_role = get_user_role(user)
                
                return Response({
                    "sessionid": sessionid,
                    "user_id": user.id,
                    "user_role": user_role, 
                    "csrf_token": csrf_token,
                    "csrf_token_expiry": csrf_token_expiry.isoformat()           
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Authentication failed, user not found."}, status=400)
        except AuthException as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
# Changes in token, refreshtoken, logout, socialauth and user view