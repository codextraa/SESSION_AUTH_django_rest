from unittest.mock import patch, MagicMock
from django.test import override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from social_core.exceptions import AuthException
from server.utils.encryption import generate_cache_key
from social_django.models import UserSocialAuth

User = get_user_model()


class SocialLoginViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.url = reverse("social-login")

        self.valid_payload = {
            "provider": "google-oauth2",
            "social_auth_code": "mock_oauth_code_456",
            "redirect_uri": "https://myapp.com/api/auth/callback/google",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

    def tearDown(self):
        cache.clear()

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_provider(self):
        """Test 400 bad request when provider name is missing."""
        payload = self.valid_payload.copy()
        del payload["provider"]

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("provider", response.data)
        self.assertEqual(response.data["provider"][0], "Provider is required.")

        payload["provider"] = None
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["provider"][0], "Provider is required.")

        payload["provider"] = ""
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["provider"][0], "Provider is required.")

    def test_missing_social_auth_code(self):
        """Test 400 bad request when social_auth_code is missing."""
        payload = self.valid_payload.copy()
        del payload["social_auth_code"]

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("social_auth_code", response.data)
        self.assertEqual(response.data["social_auth_code"][0], "Code is required.")

        payload["social_auth_code"] = None
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["social_auth_code"][0], "Code is required.")

        payload["social_auth_code"] = ""
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["social_auth_code"][0], "Code is required.")

    def test_missing_redirect_uri(self):
        """Test 400 bad request when social_auth_code is missing."""
        payload = self.valid_payload.copy()
        del payload["redirect_uri"]

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("redirect_uri", response.data)
        self.assertEqual(response.data["redirect_uri"][0], "Redirect URI is required.")

        payload["redirect_uri"] = None
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["redirect_uri"][0], "Redirect URI is required.")

        payload["redirect_uri"] = ""
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["redirect_uri"][0], "Redirect URI is required.")

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_login_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ==================================================
    # INTERNAL SERVER ERROR TEST (500)
    # ==================================================

    @patch("auth_api.views.load_strategy")
    def test_internal_server_error_on_view_crash(self, mock_load_strategy):
        """Test 500 internal server error when an unhandled system crash occurs."""
        mock_load_strategy.side_effect = Exception(
            "Unexpected database connection drop."
        )

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["error"], "Unexpected database connection drop.")


@patch(
    "social_core.backends.oauth.BaseOAuth2.request_access_token",
    return_value={"access_token": "mocked_access_token_123", "token_type": "Bearer"},
)
class SocialLoginViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.url = reverse("social-login")

        self.valid_payload = {
            "provider": "google-oauth2",
            "social_auth_code": "mock_google_oauth_code_456",
            "redirect_uri": "https://myapp.com/api/auth/callback/google",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

        self.existing_user = User.objects.create_user(
            email="defaultuser@example.com",
            username="emailuser",
            first_name="first",
            last_name="last",
            password="SecurePassword123!",
            profile_img="profile_images/default_profile.jpg",
            auth_provider="email",
            is_email_verified=True,
            is_active=True,
        )

    def tearDown(self):
        User.objects.all().delete()
        cache.clear()

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    # ------- Create -------

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_user_creation_with_first_and_last_name_picture(
        self, mock_user_data, mock_req_token
    ):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser1@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        self.assertFalse(User.objects.filter(email="googleuser1@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_keys = [
            "sessionid",
            "session_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, response.data)
            self.assertIsNotNone(response.data[key])

        self.assertTrue(User.objects.filter(email="googleuser1@example.com").exists())

        new_user = User.objects.get(email="googleuser1@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s720-c",
        )
        self.assertEqual(new_user.auth_provider, "google")
        self.assertIn("user_", new_user.username)

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_user_creation_with_fullname(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser2@example.com",
            "name": "John Kane William",
            "given_name": None,
            "family_name": None,
            "picture": "",
            "email_verified": True,
        }

        self.assertFalse(User.objects.filter(email="googleuser2@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="googleuser2@example.com").exists())

        new_user = User.objects.get(email="googleuser2@example.com")
        self.assertEqual(new_user.first_name, "John")
        self.assertEqual(new_user.last_name, "Kane William")
        self.assertEqual(
            new_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "google")

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_user_creation_with_half_fullname(
        self, mock_user_data, mock_req_token
    ):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser3@example.com",
            "name": "John",
            "given_name": None,
            "family_name": None,
            "picture": "",
            "email_verified": True,
        }

        self.assertFalse(User.objects.filter(email="googleuser3@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="googleuser3@example.com").exists())

        new_user = User.objects.get(email="googleuser3@example.com")
        self.assertEqual(new_user.first_name, "John")
        self.assertEqual(new_user.last_name, "")
        self.assertEqual(
            new_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "google")

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_user_creation_without_picture(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser4@example.com",
            "name": "John",
            "given_name": None,
            "family_name": None,
            "picture": "",
            "email_verified": True,
        }

        self.assertFalse(User.objects.filter(email="googleuser4@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="googleuser4@example.com").exists())

        new_user = User.objects.get(email="googleuser4@example.com")
        self.assertEqual(new_user.first_name, "John")
        self.assertEqual(new_user.last_name, "")
        self.assertEqual(
            new_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "google")

    @patch("social_core.backends.amazon.AmazonOAuth2.user_data")
    def test_amazon_user_creation(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "amazonuser@example.com",
            "name": "Jane Doe",
        }

        self.valid_payload["provider"] = "amazon"

        self.assertFalse(User.objects.filter(email="amazonuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="amazonuser@example.com").exists())

        new_user = User.objects.get(email="amazonuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "amazon")

    @patch(
        "social_core.backends.facebook.FacebookOAuth2.request",
        return_value=MagicMock(
            status_code=200, json=lambda: {"access_token": "mocked_fb_token"}
        ),
    )
    @patch("social_core.backends.facebook.FacebookOAuth2.user_data")
    def test_facebook_user_creation(self, mock_user_data, mock_fb_req, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "facebookuser@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
            "picture": {
                "data": {
                    "height": 200,
                    "width": 200,
                    "is_silhouette": False,
                    "url": "https://platform-lookaside.fbsbx.com/platform/profilepic/?psid=mock-image.jpg",
                }
            },
        }

        self.valid_payload["provider"] = "facebook"

        self.assertFalse(User.objects.filter(email="facebookuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="facebookuser@example.com").exists())

        new_user = User.objects.get(email="facebookuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://platform-lookaside.fbsbx.com/platform/profilepic/?psid=mock-image.jpg",
        )
        self.assertEqual(new_user.auth_provider, "facebook")

    @patch("social_core.backends.github.GithubOAuth2.user_data")
    def test_github_user_creation(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "githubuser@example.com",
            "name": "Jane Doe",
            "avatar_url": "https://avatars.githubusercontent.com/u/87654321?v=4",
            "emails": [
                {
                    "email": "githubuser@example.com",
                    "primary": "True",
                    "verified": "true",
                    "visibility": "public",
                },
                {
                    "email": "secondary@github.com",
                    "primary": False,
                    "verified": True,
                    "visibility": None,
                },
            ],
        }

        self.valid_payload["provider"] = "github"

        self.assertFalse(User.objects.filter(email="githubuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="githubuser@example.com").exists())

        new_user = User.objects.get(email="githubuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://avatars.githubusercontent.com/u/87654321?v=4",
        )
        self.assertEqual(new_user.auth_provider, "github")

    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.request_access_token",
        return_value={
            "access_token": "mocked_li_token",
            "id_token": "mock_id_token_xyz",
        },
    )
    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.validate_and_return_id_token"
    )
    @patch("social_core.backends.linkedin.LinkedinOpenIdConnect.user_data")
    def test_linkedin_user_creation(
        self, mock_user_data, mock_validate_token, mock_li_token, mock_req_token
    ):
        """Runs real pipeline. Creates new user and profile."""
        LINKEDIN_JWT_CLAIMS = {
            "sub": "auth_li_998877",
            "email": "linkedinuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
            "iat": 1718919600,
        }

        # 1. Bypass the complex cryptographic JWT signature checks and return expected token claims
        mock_validate_token.return_value = LINKEDIN_JWT_CLAIMS

        # 2. Return the mock user data dict when user info is queried
        mock_user_data.return_value = {
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "linkedinuser@example.com",
            "picture": "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
            "email_verified": True,
        }

        self.valid_payload["provider"] = "linkedin-openidconnect"

        self.assertFalse(User.objects.filter(email="linkedinuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="linkedinuser@example.com").exists())

        new_user = User.objects.get(email="linkedinuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "linkedin")

    @patch("social_core.backends.microsoft.MicrosoftOAuth2.user_data")
    def test_microsoft_user_creation(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "userPrincipalName": "microsoftuser@example.com",
            "email": "microsoftuser@example.com",
            "givenName": "Jane",
            "surname": "Doe",
            "xms_edov": True,
        }

        self.valid_payload["provider"] = "microsoft-graph"

        self.assertFalse(
            User.objects.filter(email="microsoftuser@example.com").exists()
        )

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="microsoftuser@example.com").exists())

        new_user = User.objects.get(email="microsoftuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(new_user.auth_provider, "microsoft")

    # ------- Update -------

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_user_update(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Authenticates existing active social user successfully."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        self.existing_user.profile_img = (
            "https://lh3.googleusercontent.com/a/old-mock-profile-image.jpg=s720-c"
        )
        self.existing_user.auth_provider = "google"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        user_hashed_key = generate_cache_key(self.existing_user.id)
        cache_key = f"login_failures:{user_hashed_key}"
        cache.set(cache_key, 3)

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_keys = [
            "sessionid",
            "session_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, response.data)
            self.assertIsNotNone(response.data[key])

        self.assertEqual(response.data["user_id"], self.existing_user.id)

        self.assertIsNone(cache.get(cache_key))

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s720-c",
        )
        self.assertEqual(self.existing_user.auth_provider, "google")

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    @override_settings(
        AWS_STORAGE_BUCKET_NAME="my-mock-bucket",
        ALLOWED_HOSTS=["myapp.com", "localhost", "testserver"],
    )
    def test_google_user_update_skipped(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Authenticates existing active social user successfully."""

        # * First case where the image is local

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        self.existing_user.auth_provider = "google"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "google")

        # * Second case where the image is from s3

        self.headers["HTTP_X_CSRFTOKEN"] = response1.data["csrf_token"]

        s3_image_url = "https://my-mock-bucket.s3.amazonaws.com/real-estate/profile_images/avatar.jpg"
        self.existing_user.profile_img = s3_image_url
        self.existing_user.save()

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(
            self.existing_user.profile_img,
            s3_image_url,
        )

        # * Third case where the image is from s3

        self.headers["HTTP_X_CSRFTOKEN"] = response2.data["csrf_token"]

        allowed_host_image_url = (
            "https://myapp.com/media/profile_images/custom_avatar.jpg"
        )
        self.existing_user.profile_img = allowed_host_image_url
        self.existing_user.save()

        response3 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response3.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(
            self.existing_user.profile_img.name,
            allowed_host_image_url,
        )

    @patch("social_core.backends.amazon.AmazonOAuth2.user_data")
    def test_amazon_user_update(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "defaultuser@example.com",
            "name": "Jane Doe",
        }

        self.valid_payload["provider"] = "amazon"

        self.existing_user.auth_provider = "amazon"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "amazon")

    @patch(
        "social_core.backends.facebook.FacebookOAuth2.request",
        return_value=MagicMock(
            status_code=200, json=lambda: {"access_token": "mocked_fb_token"}
        ),
    )
    @patch("social_core.backends.facebook.FacebookOAuth2.user_data")
    def test_facebook_user_update(self, mock_user_data, mock_fb_req, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "defaultuser@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
            "picture": {
                "data": {
                    "height": 200,
                    "width": 200,
                    "is_silhouette": False,
                    "url": "https://platform-lookaside.fbsbx.com/platform/profilepic/?psid=mock-image.jpg",
                }
            },
        }

        self.valid_payload["provider"] = "facebook"

        self.existing_user.profile_img = "https://platform-lookaside.fbsbx.com/platform/profilepic/?psid=old-mock-image.jpg"
        self.existing_user.auth_provider = "facebook"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "https://platform-lookaside.fbsbx.com/platform/profilepic/?psid=mock-image.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "facebook")

    @patch("social_core.backends.github.GithubOAuth2.user_data")
    def test_github_user_update(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "email": "defaultuser@example.com",
            "name": "Jane Doe",
            "avatar_url": "https://avatars.githubusercontent.com/u/87654321?v=4/mock-profile-image.jpg",
            "emails": [
                {
                    "email": "defaultuser@example.com",
                    "primary": "True",
                    "verified": "true",
                    "visibility": "public",
                },
                {
                    "email": "secondary@github.com",
                    "primary": False,
                    "verified": True,
                    "visibility": None,
                },
            ],
        }

        self.valid_payload["provider"] = "github"

        self.existing_user.profile_img = "https://avatars.githubusercontent.com/u/87654321?v=4/old-mock-profile-image.jpg"
        self.existing_user.auth_provider = "github"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "https://avatars.githubusercontent.com/u/87654321?v=4/mock-profile-image.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "github")

    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.request_access_token",
        return_value={
            "access_token": "mocked_li_token",
            "id_token": "mock_id_token_xyz",
        },
    )
    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.validate_and_return_id_token"
    )
    @patch("social_core.backends.linkedin.LinkedinOpenIdConnect.user_data")
    def test_linkedin_user_update(
        self, mock_user_data, mock_validate_token, mock_li_token, mock_req_token
    ):
        """Runs real pipeline. Creates new user and profile."""
        LINKEDIN_JWT_CLAIMS = {
            "sub": "auth_li_998877",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
            "iat": 1718919600,
        }

        # 1. Bypass the complex cryptographic JWT signature checks and return expected token claims
        mock_validate_token.return_value = LINKEDIN_JWT_CLAIMS

        # 2. Return the mock user data dict when user info is queried
        mock_user_data.return_value = {
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "defaultuser@example.com",
            "picture": "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
            "email_verified": True,
        }

        self.valid_payload["provider"] = "linkedin-openidconnect"

        self.existing_user.profile_img = (
            "https://media.licdn.com/dms/image/v2/old-mock-profile.jpg"
        )
        self.existing_user.auth_provider = "linkedin"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "https://media.licdn.com/dms/image/v2/mock-profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "linkedin")

    @patch("social_core.backends.microsoft.MicrosoftOAuth2.user_data")
    def test_microsoft_user_update(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Creates new user and profile."""
        mock_user_data.return_value = {
            "userPrincipalName": "defaultuser@example.com",
            "email": "defaultuser@example.com",
            "givenName": "Jane",
            "surname": "Doe",
            "xms_edov": True,
        }

        self.valid_payload["provider"] = "microsoft-graph"

        self.existing_user.auth_provider = "microsoft"
        self.existing_user.save()

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "microsoft")

    # ------- Scenerios -------

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_login_existing_email_user_without_update_success(
        self, mock_user_data, mock_req_token
    ):
        """Runs real pipeline. Authenticates existing active social user successfully."""

        # * First case where google social user doesn't exist (grabs the user)

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        self.assertTrue(User.objects.filter(email="defaultuser@example.com").exists())

        user_hashed_key = generate_cache_key(self.existing_user.id)
        cache_key = f"login_failures:{user_hashed_key}"
        cache.set(cache_key, 3)

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        expected_keys = [
            "sessionid",
            "session_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, response1.data)
            self.assertIsNotNone(response1.data[key])

        self.assertEqual(response1.data["user_id"], self.existing_user.id)

        self.assertIsNone(cache.get(cache_key))

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "email")
        self.assertEqual(self.existing_user.username, "emailuser")

        link = UserSocialAuth.objects.get(user=self.existing_user)
        self.assertEqual(link.provider, "google-oauth2")
        self.assertEqual(link.uid, "110169484474386276334")

        # * Second case where google social user exists (only login)

        self.headers["HTTP_X_CSRFTOKEN"] = response1.data["csrf_token"]

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)

        self.existing_user.refresh_from_db()
        self.assertEqual(self.existing_user.first_name, "first")
        self.assertEqual(self.existing_user.last_name, "last")
        self.assertEqual(
            self.existing_user.profile_img,
            "profile_images/default_profile.jpg",
        )
        self.assertEqual(self.existing_user.auth_provider, "email")
        self.assertEqual(self.existing_user.username, "emailuser")
        self.assertEqual(response1.data["user_id"], response2.data["user_id"])

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_login_creation_plus_update_success(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Create, Authenticate and Update existing active social user successfully."""

        # * First case where google social user doesn't exist (create)

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s96-c",
            "email_verified": True,
        }

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        new_user = User.objects.get(email="googleuser@example.com")
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://lh3.googleusercontent.com/a/mock-profile-image.jpg=s720-c",
        )
        self.assertEqual(new_user.auth_provider, "google")

        link = UserSocialAuth.objects.get(user=new_user)
        self.assertEqual(link.provider, "google-oauth2")

        # * Second case where google social user exists (update)

        self.headers["HTTP_X_CSRFTOKEN"] = response1.data["csrf_token"]

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "googleuser@example.com",
            "given_name": "John",
            "family_name": "Kane William",
            "picture": "https://lh3.googleusercontent.com/a/mock-profile-image2.jpg=s96-c",
            "email_verified": True,
        }

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)

        new_user.refresh_from_db()
        self.assertEqual(new_user.first_name, "Jane")
        self.assertEqual(new_user.last_name, "Doe")
        self.assertEqual(
            new_user.profile_img,
            "https://lh3.googleusercontent.com/a/mock-profile-image2.jpg=s720-c",
        )
        self.assertEqual(new_user.auth_provider, "google")
        self.assertEqual(response1.data["user_id"], response2.data["user_id"])

    # ==========================================
    # USER AUTHENTICATION FAILURE (401)
    # ==========================================

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_social_provider_auth_failed(self, mock_user_data, mock_req_token):
        """Test 401 response with generic message when AuthException is raised."""
        mock_user_data.side_effect = AuthException(None, "Invalid token signature")

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["error"],
            "Social authentication failed. Something went wrong.",
        )

    # ==========================================
    # CRITICAL ATTRIBUTE VALIDATIONS (403)
    # ==========================================

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_social_login_staff_user_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is staff."""
        self.existing_user.is_staff = True
        self.existing_user.save()

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Authentication failed. Please verify your credentials or try a different login method.",
        )

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_social_login_deactivated_user_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is deactivated."""
        self.existing_user.is_active = False
        self.existing_user.save()

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"], "Account has been deactivated. Contact your admin"
        )

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_social_login_unverified_email_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when email is unverified."""
        self.existing_user.is_email_verified = False
        self.existing_user.save()

        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Email is not verified. You must verify your email first",
        )

    # ------- Impersonations -------

    @patch("social_core.backends.google.GoogleOAuth2.user_data")
    def test_google_login_impersonation_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is impersonated."""
        mock_user_data.return_value = {
            "sub": "110169484474386276334",
            "email": "defaultuser@example.com",
            "email_verified": False,
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Sorry your email is not verified by the provider. Please verify your email first.",
        )

    @patch("social_core.backends.facebook.FacebookOAuth2.user_data")
    def test_facebook_login_impersonation_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is impersonated."""
        mock_user_data.return_value = {
            "first_name": "Jane",
            "last_name": "Doe",
        }

        self.valid_payload["provider"] = "facebook"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        # Auth Exception gets trigger before the code reaches Forbidden validation
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("social_core.backends.github.GithubOAuth2.user_data")
    def test_github_login_impersonation_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is impersonated."""
        mock_user_data.return_value = {
            "email": "defaultuser@example.com",
            "emails": [
                {
                    "email": "defaultuser@example.com",
                    "primary": True,
                    "verified": False,
                    "visibility": "public",
                },
                {
                    "email": "secondary@github.com",
                    "primary": False,
                    "verified": True,
                    "visibility": None,
                },
            ],
        }

        self.valid_payload["provider"] = "github"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Sorry your email is not verified by the provider. Please verify your email first.",
        )

    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.request_access_token",
        return_value={
            "access_token": "mocked_li_token",
            "id_token": "mock_id_token_xyz",
        },
    )
    @patch(
        "social_core.backends.linkedin.LinkedinOpenIdConnect.validate_and_return_id_token"
    )
    @patch("social_core.backends.linkedin.LinkedinOpenIdConnect.user_data")
    def test_linkedin_login_impersonation_fails(
        self, mock_user_data, mock_validate_token, mock_li_token, mock_req_token
    ):
        """Runs real pipeline. Custom pipeline raises 403 when user is impersonated."""
        LINKEDIN_JWT_CLAIMS = {
            "sub": "auth_li_998877",
            "email": "defaultuser@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "iat": 1718919600,
        }

        # 1. Bypass the complex cryptographic JWT signature checks and return expected token claims
        mock_validate_token.return_value = LINKEDIN_JWT_CLAIMS

        # 2. Return the mock user data dict when user info is queried
        mock_user_data.return_value = {
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "defaultuser@example.com",
            "email_verified": False,
        }

        self.valid_payload["provider"] = "linkedin-openidconnect"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Sorry your email is not verified by the provider. Please verify your email first.",
        )

    @patch("social_core.backends.microsoft.MicrosoftOAuth2.user_data")
    def test_microsoft_login_impersonation_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is impersonated."""
        mock_user_data.return_value = {
            "userPrincipalName": "defaultuser@example.com",
            "email": "defaultuser@example.com",
            "xms_edov": False,
        }

        self.valid_payload["provider"] = "microsoft-graph"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Sorry your email is not verified by the provider. Please verify your email first.",
        )

    # ------- Linkups -------

    @patch("social_core.backends.amazon.AmazonOAuth2.user_data")
    def test_amazon_login_linkup_fails(self, mock_user_data, mock_req_token):
        """Runs real pipeline. Custom pipeline raises 403 when user is linked up."""
        mock_user_data.return_value = {
            "email": "defaultuser@example.com",
            "name": "Jane Doe",
        }

        self.valid_payload["provider"] = "amazon"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "You cannot log into an existing account using Amazon. Please log in using your original method.",
        )

    # ==========================================
    # USER NOT FOUND (404)
    # ==========================================

    @patch("auth_api.views.load_backend")
    @patch("auth_api.views.load_strategy")
    def test_resolved_user_not_found(
        self, mock_load_strategy, mock_load_backend, mock_req_token
    ):
        """Test 404 response when PSA returns None after auth."""
        mock_backend = MagicMock()
        mock_backend.auth_complete.return_value = None
        mock_load_backend.return_value = mock_backend

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["error"], "Authentication error. User not found")
