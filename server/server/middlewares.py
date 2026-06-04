import sys
from django.http import HttpResponseForbidden
from django.conf import settings


class RestrictDirectApiMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if "test" in sys.argv:
            return self.get_response(request)

        if request.path.startswith("/auth-api/"):
            api_key = request.headers.get("NEXT-X-API-KEY")
            if api_key != settings.NEXT_API_SECRET_KEY:
                return HttpResponseForbidden(
                    "Direct access to this API is not allowed."
                )
        response = self.get_response(request)
        return response
