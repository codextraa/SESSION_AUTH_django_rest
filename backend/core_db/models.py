"""JWT User Model"""

import re
import secrets
import string
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, RegexValidator
from phonenumber_field.modelfields import PhoneNumberField


class UserManager(BaseUserManager):
    """Custom User Manager"""

    def create_user(self, email, password=None, **extra_fields):
        """Custom User Creation"""
        if not email:
            raise ValueError("You must have an email address")

        try:
            validate_email(email)
        except ValidationError as exc:
            raise ValidationError("Invalid Email Format") from exc

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
            user.save(using=self._db)

        return user

    def create_superuser(self, email, password, **extra_fields):
        """Super User Creation"""
        if not password:
            raise ValueError("SuperUser must have a password")

        extra_fields.setdefault("is_email_verified", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User Class"""

    class Meta:
        ordering = ["email"]

    AUTH_PROVIDER = [
        ("email", "Email"),
        ("google", "Google"),
        ("facebook", "Facebook"),
        ("instagram", "Instagram"),
        ("twitter", "Twitter"),
        ("linkedin", "LinkedIn"),
        ("github", "GitHub"),
    ]
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r"^\S+$",  # No whitespace allowed
                message="Username cannot contain spaces",
                code="invalid_username",
            )
        ],
    )
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    phone_number = PhoneNumberField(unique=True, blank=True, null=True)
    profile_img = models.ImageField(
        upload_to="profile_images/", blank=True, null=True, max_length=500
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login_time = models.DateTimeField(blank=True, null=True)
    auth_provider = models.CharField(
        max_length=20, choices=AUTH_PROVIDER, default="email"
    )
    slug = models.SlugField(unique=True, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def _pass_valid(self, password):
        """Private method for testing valid password"""
        if password:
            if (
                len(password) < 8
                or not re.search(r"[a-z]", password)
                or not re.search(r"[A-Z]", password)
                or not re.search(r"[0-9]", password)
                or not re.search(r"[!@#$%^&*(),.?\":{}|<>[\]~/\\']", password)
            ):
                raise ValidationError(
                    "Password must contain at least 8 characters, "
                    "including an uppercase letter, a lowercase letter, "
                    "a number, and a special character."
                )

    @staticmethod
    def create_random_password(length=16):
        """
        Generate a cryptographically secure random password of the given length.
        Ensures at least one uppercase letter, one lowercase letter, one digit,
        and one special character are included in the password.
        """
        if length < 4:
            raise ValueError(
                "Password length must be at least 4 characters to meet the requirements"
            )

        # Define the character sets
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        punctuation = string.punctuation

        # Ensure at least one of each character type
        password = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits),
            secrets.choice(punctuation),
        ]

        # Fill the rest of the password length with random characters from all sets
        alphabet = lower + upper + digits + punctuation
        password += [secrets.choice(alphabet) for _ in range(length - 4)]

        # Shuffle the password to mix the characters
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def set_password(self, raw_password):
        """Validates raw password before hashing"""
        self._pass_valid(raw_password)
        super().set_password(raw_password)

    def save(self, *args, **kwargs):
        """Running Validators before saving"""
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        """Return Email"""
        return f"{self.email}"
