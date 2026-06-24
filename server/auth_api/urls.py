from django.urls import path
from . import views

urlpatterns = [
    path("csrf-token/", views.CSRFTokenView.as_view(), name="csrf-token"),
    path(
        "recaptcha-verify/",
        views.RecaptchaValidationView.as_view(),
        name="recaptcha-verify",
    ),
    path("login/", views.LoginView.as_view(), name="login"),
    path("two-fa-login/", views.TwoFAView.as_view(), name="two-fa-login"),
]
