"""Admin forms."""

from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model


User = get_user_model()


class CustomUserCreationForm(UserCreationForm):
    """User Creation Form."""

    class Meta:
        model = User
        fields = ("email", "username", "password1", "password2")

    def clean(self):
        """Custom validation."""
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        username = cleaned_data.get("username")
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if not email:
            raise ValidationError("Email is required.")

        if not username:
            raise ValidationError("Username is required.")

        if not password1:
            raise ValidationError("Password is required.")

        if password1 != password2:
            raise ValidationError("Passwords do not match.")

        if User.objects.filter(email=email).exists():
            raise ValidationError("Email already exists.")

        if User.objects.filter(username=username).exists():
            raise ValidationError("Username already exists.")

        return cleaned_data
