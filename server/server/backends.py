from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.db.models import Q

User = get_user_model()


class CustomAuthBackend(ModelBackend):
    def authenticate(
        self, request, username=None, password=None, **kwargs
    ):  # pylint: disable=R0911
        # 'username' here represents the raw input from email_or_username
        if username is None:
            return None

        try:
            user = User.objects.get(
                Q(email__exact=username.lower()) | Q(username__exact=username)
            )
        except User.DoesNotExist:
            decoy_hash = "pbkdf2_sha256$1$invalid_salt$invalid_hash"
            hasher = identify_hasher(decoy_hash)  # creates the hasher
            # Burning expected CPU cycles to neutralize timing attacks
            hasher.verify(password, decoy_hash)

            return None

        # Adding the user object to the request
        request.authenticated_user_obj = user

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
