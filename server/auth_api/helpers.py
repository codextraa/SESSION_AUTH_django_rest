from rest_framework.response import Response
from rest_framework import status


def extract_recaptcha_data(request):
    """Extracts recaptcha token and version from the request data and
    extracts user_agent and user_ip from the request headers."""

    recaptcha_token = request.data.get("recaptcha_token")
    if recaptcha_token is None:
        return Response(
            {"error": "Missing reCAPTCHA token."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    recaptcha_version = request.data.get("recaptcha_version")
    if recaptcha_version is None:
        return Response(
            {"error": "Missing reCAPTCHA version."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_agent = request.META.get("HTTP_USER_AGENT", "")
    if user_agent == "":
        return Response(
            {"error": "Missing User Agent."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_ip = request.META.get(
        "HTTP_X_FORWARDED_FOR", request.META.get("HTTP_X_REAL_IP", "")
    )
    if user_ip == "":
        return Response(
            {"error": "Missing User IP Address."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if "," in user_ip:
        user_ip = user_ip.split(",")[0].strip()

    return {
        "recaptcha_token": recaptcha_token,
        "recaptcha_version": recaptcha_version,
        "user_ip": user_ip,
        "user_agent": user_agent,
    }
