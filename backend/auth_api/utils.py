import random
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from django.core.cache import cache
from django.conf import settings
from django.core.mail import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# from twilio.rest import Client


APP_NAME = settings.APP_NAME

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailOtp:
    """Email Otp Sender (used during Login)"""

    @staticmethod
    def generate_otp():
        """Generate a 6 digit OTP."""
        otp = random.randint(100000, 999999)
        return otp

    @staticmethod
    def send_email_otp(email, otp):
        """Send an OTP to the user's email."""
        try:
            email = EmailMessage(
                subject="2 Factor Login Authentication",
                body=(
                    f"Hi {email}, Welcome to {APP_NAME}\n\n"
                    f"Your OTP code is: {otp}\n\n"
                    "The OTP will expire in 10 minutes"
                ),
                to=[email],
            )
            email.send()

            return True
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error sending email: %s", e)
            return False

    @staticmethod
    def verify_otp(user_id, request_otp):
        """Verify the OTP sent to the user's email."""
        stored_otp = cache.get(f"otp_{user_id}")

        try:
            request_otp = int(request_otp)
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error sending email: %s", e)
            return False

        if stored_otp != request_otp:
            return False
        cache.delete(f"otp_{request_otp}")
        return True


class EmailLink:
    """Email Link Sender and Verifier."""

    SECRET_KEY = settings.SECRET_KEY
    SALT = "email-verification"
    EXPIRY_SECONDS = 600  # 10 minutes
    FRONTEND_URL = settings.FRONTEND_URL

    @classmethod
    def _generate_link(cls, email, action):
        """Generate a signed token for the email."""
        serializer = URLSafeTimedSerializer(cls.SECRET_KEY)
        token = serializer.dumps(email, salt=cls.SALT)

        # Adding expiry metadata
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=cls.EXPIRY_SECONDS)
        expiry_timestamp = int(expiry_time.timestamp())

        params = {
            "token": token,
            "expiry": expiry_timestamp,
        }
        query_string = urlencode(params)

        if action == "email-verification":
            return f"{cls.FRONTEND_URL}/auth/verify-email/?{query_string}"
        if action == "password-reset":
            return f"{cls.FRONTEND_URL}/auth/reset-password/?{query_string}"
        raise ValueError("Invalid action.")

    @classmethod
    def verify_link(cls, token):
        """Verify the token and return the email."""
        serializer = URLSafeTimedSerializer(cls.SECRET_KEY)
        try:
            email = serializer.loads(token, salt=cls.SALT, max_age=cls.EXPIRY_SECONDS)
            return email
        except SignatureExpired as exc:
            raise ValueError("The verification link has expired.") from exc
        except BadSignature as exc:
            raise ValueError("Invalid verification link.") from exc

    @classmethod
    def send_email_link(cls, email):
        """Send the email with the verification link."""
        link = cls._generate_link(email, "email-verification")

        try:
            email_message = EmailMessage(
                subject="Verify Your Email",
                body=(
                    f"Hi {email}, Welcome to {APP_NAME}\n\n"
                    "Please verify your email using the following "
                    f"link: {link}\n\nThis link will expire in 10 minutes."
                ),
                to=[email],
            )
            email_message.send()
            return True
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error sending email: %s", e)
            return False

    @classmethod
    def send_password_reset_link(cls, email):
        """Send the email with the password reset link."""
        link = cls._generate_link(email, "password-reset")

        try:
            email_message = EmailMessage(
                subject="Reset Your Password",
                body=(
                    f"Hi {email}, Welcome to {APP_NAME}\n\n"
                    "Please reset your password using the following "
                    f"link: {link}\n\nThis link will expire in 10 minutes."
                ),
                to=[email],
            )
            email_message.send()
            return True
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error sending email: %s", e)
            return False


class PhoneOtp:
    """Phone Otp Sender (used during Login)"""

    TWILIO_ACCOUNT_SID = settings.TWILIO_ACCOUNT_SID
    TWILIO_AUTH_TOKEN = settings.TWILIO_AUTH_TOKEN
    TWILIO_PHONE_NUMBER = settings.TWILIO_PHONE_NUMBER

    @classmethod
    def generate_otp(cls):
        """Generate a 6 digit OTP."""
        otp = random.randint(100000, 999999)
        return otp

    @classmethod
    def send_otp(cls, email, phone):  # pylint: disable=unused-argument
        """Send an OTP to the user's phone."""
        try:
            # phone_otp = cls.generate_otp()
            # client = Client(cls.TWILIO_ACCOUNT_SID, cls.TWILIO_AUTH_TOKEN)

            # client.messages.create(
            #     body=(
            #         f"Hi {email}, Welcome to {APP_NAME}\n\n"
            #         "Your OTP code is: {phone_otp}. "
            #         "This otp will expire in 10 minutes"
            #     ),
            #     from_=cls.TWILIO_PHONE_NUMBER,
            #     to=phone
            # )
            phone_otp = 000000  # For testing
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error sending email: %s", e)
            return False

        cache.set(f"phone_otp_{phone}", phone_otp, 600)

        return True

    @classmethod
    def verify_otp(cls, phone, request_otp):
        """Verify the OTP sent to the user's phone."""
        stored_otp = cache.get(f"phone_otp_{phone}")

        try:
            request_otp = int(request_otp)
        except ValueError:
            return False

        if stored_otp != request_otp:
            return False
        cache.delete(f"phone_otp_{phone}")
        return True
