"""Admin registration for blog api."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User
from .forms import CustomUserCreationForm


class UserAdmin(BaseUserAdmin):
    """Custom User Admin"""

    list_display = ("email", "username")
    list_filter = ("groups",)
    prepopulated_fields = {"slug": ("username",)}

    # Fields to be displayed on the user detail page
    fieldsets = (
        (None, {"fields": ("email", "username", "password", "slug", "auth_provider")}),
        (
            "Personal_info",
            {"fields": ("first_name", "last_name", "phone_number", "profile_img")},
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_email_verified",
                    "is_phone_verified",
                    "failed_login_attempts",
                    "last_failed_login_time",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Important dates", {"fields": ("last_login",)}),
    )

    add_form = CustomUserCreationForm
    # Fields to be displayed in user creation form
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "username",
                    "slug",
                    "password1",
                    "password2",
                    "is_active",
                    "is_staff",
                ),
            },
        ),
    )


admin.site.register(User, UserAdmin)
