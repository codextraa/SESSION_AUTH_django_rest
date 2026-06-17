from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from rest_framework.throttling import BaseThrottle
from server.utils.encryption import generate_cache_key

User = get_user_model()


def calculate_remaining_ttl(cache_key):
    """
    Calculate the remaining TTL for the cache key.
    """
    ttl = None
    if hasattr(cache, "ttl"):
        ttl = cache.ttl(cache_key)
    if ttl and ttl > 0:
        return max(ttl, 1)

    return 60


class OTPCooldownThrottle(BaseThrottle):
    def __init__(self):
        self.remaining_ttl = 60

    def allow_request(self, request, view):  # pylint: disable=R0911
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """

        login_input = (
            request.data.get("email_or_username")
            if isinstance(request.data, dict)
            else None
        )

        if login_input:
            try:
                clean_input = str(login_input).strip()
                user = User.objects.only("id").get(
                    Q(email__exact=clean_input.lower()) | Q(username__exact=clean_input)
                )
                user_id = user.id
            except User.DoesNotExist:
                return True  # Serializer will return 400

            user_lock_key = generate_cache_key(user_id)
            user_cache_key = f"otp_cooldown:{user_id}:{user_lock_key}"

            if cache.get(user_cache_key):
                self.remaining_ttl = calculate_remaining_ttl(user_cache_key)
                return False

        return True

    def wait(self):
        """
        Return the number of seconds to wait for the next request.
        """
        return self.remaining_ttl
