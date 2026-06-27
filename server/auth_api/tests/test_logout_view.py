from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

User = get_user_model()


class LogoutViewTests(APITestCase):
    """Integration tests for the LogoutView endpoint without using mocks."""

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("logout")

        self.user = User.objects.create_user(
            email="testuser@example.com",
            username="testuser",
            password="SecurePassword123!",
        )

        login_success = self.client.login(
            username="testuser",
            password="SecurePassword123!",
        )
        self.assertTrue(
            login_success,
            "Client login failed. Check credentials/user model configuration.",
        )

        session = self.client.session
        session.modified = True
        session.save()

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

    def tearDown(self):
        User.objects.all().delete()
        cache.clear()

    # ==========================================
    # SUCCESS TEST (200)
    # ==========================================

    def test_logout_success(self):
        """An authenticated user can logout."""
        old_session_key = self.client.session.session_key
        old_cache_key = f"django.contrib.sessions.cached_db{old_session_key}"
        self.assertIsNotNone(cache.get(old_cache_key))

        self.assertTrue(old_session_key)
        self.assertTrue(Session.objects.filter(session_key=old_session_key).exists())

        response = self.client.post(self.url, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"success": "Logged out successfully"})

        self.assertFalse(Session.objects.filter(session_key=old_session_key).exists())
        self.assertIsNone(cache.get(old_cache_key))

    # ==========================================
    # UNAUTHORIZED TEST (403)
    # ==========================================

    def test_logout_unauthorized(self):
        """A user without an active session cannot access the view."""
        self.client.logout()

        response = self.client.post(self.url, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_logout_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(self.url, format="json", **csrf_less_headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
