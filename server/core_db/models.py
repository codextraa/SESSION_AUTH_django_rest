from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from phonenumber_field.modelfields import PhoneNumberField
from server.validators import validate_username_format, validate_password_complexity

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
        validators=[validate_username_format], 
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
    is_two_fa = models.BooleanField(default=True)
    auth_provider = models.CharField(
        max_length=20, choices=AUTH_PROVIDER, default="email"
    )
    slug = models.SlugField(unique=True, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def set_password(self, raw_password):
        """Validates raw password before hashing"""
        if not raw_password:
            raise ValidationError({"password": "Password is required"})
        errors = validate_password_complexity(raw_password)
        if len(errors["password"]) > 0:
            raise ValidationError(errors)
        super().set_password(raw_password)

    def save(self, *args, **kwargs):
        """Running Validators before saving"""
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        """Return Email"""
        return f"{self.email}"