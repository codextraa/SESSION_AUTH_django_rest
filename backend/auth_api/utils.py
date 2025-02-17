import random, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from django.core.cache import cache
from django.conf import settings
from django.core.mail import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
# from twilio.rest import Client


APP_NAME = settings.APP_NAME

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
                subject = '2 Factor Login Authentication',
                body = f'Hi {email}, Welcome to {APP_NAME}\n\nYour OTP code is: {otp}\n\nThe OTP will expire in 10 minutes',
                to = [email]
            )
            email.send()
            
            return True
        except Exception as e:
            return False
        
    @staticmethod
    def verify_otp(user_id, request_otp):
        """Verify the OTP sent to the user's email."""
        stored_otp = cache.get(f'otp_{user_id}')
        
        try:
            request_otp = int(request_otp)
        except Exception as e:
            # print(e)
            return False
        
        if stored_otp != request_otp:
            return False
        else:
            cache.delete(f'otp_{request_otp}')
            return True
        
class EmailLink:
    """Email Link Sender and Verifier."""
    SECRET_KEY = settings.SECRET_KEY
    SALT = "email-verification"
    EXPIRY_SECONDS = 600  # 10 minutes
    FRONTEND_URL = settings.FRONTEND_URL
    BASE_ROUTE = settings.BASE_ROUTE

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
        
        # return f"{settings.FRONTEND_URL}/verify-email/{token}"
        if action == 'email-verification':
            return f"{cls.FRONTEND_URL}{cls.BASE_ROUTE}/auth/verify-email/?{query_string}"
        elif action == 'password-reset':
            return f"{cls.FRONTEND_URL}{cls.BASE_ROUTE}/auth/reset-password/?{query_string}"
        else:
            raise ValueError("Invalid action.")

    @classmethod
    def verify_link(cls, token):
        """Verify the token and return the email."""
        serializer = URLSafeTimedSerializer(cls.SECRET_KEY)
        try:
            email = serializer.loads(token, salt=cls.SALT, max_age=cls.EXPIRY_SECONDS)
            return email
        except SignatureExpired:
            raise ValueError("The verification link has expired.")
        except BadSignature:
            raise ValueError("Invalid verification link.")

    @classmethod
    def send_email_link(cls, email):
        """Send the email with the verification link."""
        link = cls._generate_link(email, 'email-verification')
        
        try:
            email_message = EmailMessage(
                subject="Verify Your Email",
                body=f"Hi {email}, Welcome to {APP_NAME}\n\nPlease verify your email using the following link: {link}\n\nThis link will expire in 10 minutes.",
                to=[email]
            )
            email_message.send()
            return True
        except Exception as e:
            return False
        
    @classmethod
    def send_password_reset_link(cls, email):
        """Send the email with the password reset link."""
        link = cls._generate_link(email, 'password-reset')
        
        try:
            email_message = EmailMessage(
                subject="Reset Your Password",
                body=f"Hi {email}, Welcome to {APP_NAME}\n\nPlease reset your password using the following link: {link}\n\nThis link will expire in 10 minutes.",
                to=[email]
            )
            email_message.send()
            return True
        except Exception as e:
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
    def send_otp(cls, email, phone):
        """Send an OTP to the user's phone."""
        try:
            # phone_otp = cls.generate_otp()
            # client = Client(cls.TWILIO_ACCOUNT_SID, cls.TWILIO_AUTH_TOKEN)
            
            # client.messages.create(
            #     body=f'Hi {email}, Welcome to {APP_NAME}\n\nYour OTP code is: {phone_otp}. This otp will expire in 10 minutes',
            #     from_=cls.TWILIO_PHONE_NUMBER,
            #     to=phone
            # )
            phone_otp = 000000 # For testing
        except Exception as e:
            print(e)
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
        else:
            cache.delete(f"phone_otp_{phone}")
            return True
        