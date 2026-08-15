from unittest.mock import patch
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from core_db.models import FCMToken

User = get_user_model()


class FCMTokenViewTestCase(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.url = reverse("fcm-register")

        self.user1 = User.objects.create_user(
            username="user1", email="user1@example.com", password="Password123!"
        )
        self.user2 = User.objects.create_user(
            username="user2", email="user2@example.com", password="Password123!"
        )

        self.valid_token = "f3X8kPzQ6xE:APA91bHwM1C7eXzR-FCM-TOKEN"
        self.payload = {"fcm_token": self.valid_token}

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

        self.client.force_authenticate(user=self.user1)

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    def test_register_fcm_token_success(self):
        """Test successful registration of a new FCM token for an authenticated user."""
        response = self.client.post(
            self.url, self.payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data, {"success": "FCM token registered successfully"}
        )

        token_obj = FCMToken.objects.get(token=self.valid_token)
        self.assertEqual(token_obj.user, self.user1)

    def test_reassign_existing_fcm_token_to_new_user(self):
        """Test that an existing token is reassigned when a new user logs in on the same device."""
        # Pre-bind token to User 1
        FCMToken.objects.create(user=self.user1, token=self.valid_token)

        # Authenticate as User 2 and send the exact same browser token
        self.client.force_authenticate(user=self.user2)
        response = self.client.post(
            self.url, self.payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify DB updated ownership without throwing duplicate errors
        token_obj = FCMToken.objects.get(token=self.valid_token)
        self.assertEqual(token_obj.user, self.user2)
        self.assertEqual(FCMToken.objects.count(), 1)

    def test_user_can_register_multiple_tokens(self):
        """Test that a single user can maintain multiple device tokens."""
        second_token = "another_device_token_abc_123"

        self.client.post(self.url, self.payload, format="json", **self.headers)
        self.client.post(
            self.url, {"fcm_token": second_token}, format="json", **self.headers
        )

        self.assertEqual(FCMToken.objects.filter(user=self.user1).count(), 2)

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_fcm_token(self):
        """Test 400 bad request when fcm_token is missing."""
        payload = self.payload.copy()
        del payload["fcm_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("fcm_token", response.data)
        self.assertEqual(response.data["fcm_token"][0], "Token is required.")

        payload["fcm_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("fcm_token", response.data)
        self.assertEqual(response.data["fcm_token"][0], "Token is required.")

        payload["fcm_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("fcm_token", response.data)
        self.assertEqual(response.data["fcm_token"][0], "Token is required.")

    # ==========================================
    # USER AUTHENTICATION FAILURE (403)
    # ==========================================

    def test_register_fcm_token_unauthenticated(self):
        """Test 403 forbidden when request lacks authentication credentials."""
        self.client.logout()

        response = self.client.post(
            self.url, self.payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_register_fcm_token_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ==================================================
    # INTERNAL SERVER ERROR TEST (500)
    # ==================================================

    @patch("core_db.models.FCMToken.objects.update_or_create")
    def test_register_fcm_token_internal_server_error(self, mock_update_or_create):
        """Test 500 internal server response when unexpected database/system exception occurs."""
        mock_update_or_create.side_effect = Exception("Database connection failure")

        response = self.client.post(
            self.url, self.payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("error", response.data)
        self.assertEqual(response.data["error"], "Database connection failure")
