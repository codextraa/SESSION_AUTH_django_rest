from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from server.utils.encryption import generate_hash_key, encrypt_data

User = get_user_model()


class ResendOTPViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("resend-otp")

        self.valid_payload = {
            "pre_auth_token": "mock_pre_auth_token",
            "recaptcha_token": "mock_token_123",
            "recaptcha_version": "v3",
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

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="resend-otp", score=0.9
    ):
        """Helper to build a mock Google reCAPTCHA Enterprise response object."""
        mock_response = MagicMock()

        mock_response.token_properties.valid = valid
        mock_response.token_properties.invalid_reason = reason
        mock_response.token_properties.action = action
        mock_response.risk_analysis.score = score

        return mock_response

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_pre_auth_token(self):
        """Test 400 bad request when pre auth token is missing."""
        payload = self.valid_payload.copy()
        del payload["pre_auth_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

        payload["pre_auth_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

        payload["pre_auth_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

    def test_missing_recaptcha_token(self):
        """Test 400 bad request when recaptcha_token is missing."""
        payload = self.valid_payload.copy()
        del payload["recaptcha_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

        payload["recaptcha_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

        payload["recaptcha_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

    def test_missing_recaptcha_version(self):
        """Test 400 bad request when recaptcha_version is missing."""
        payload = self.valid_payload.copy()
        del payload["recaptcha_version"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

        payload["recaptcha_version"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

        payload["recaptcha_version"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

    def test_missing_user_agent_header(self):
        """Test 400 bad request when HTTP_USER_AGENT header is missing."""
        headers = self.headers.copy()
        del headers["HTTP_USER_AGENT"]

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_agent", response.data)
        self.assertEqual(response.data["user_agent"], "Missing User Agent Header.")

    def test_missing_user_ip_header(self):
        """Test 400 bad request when IP headers are missing."""
        headers = self.headers.copy()
        del headers["HTTP_X_REAL_IP"]

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_ip", response.data)
        self.assertEqual(response.data["user_ip"], "Missing User IP Address.")

    # ==========================================
    # RECAPTCHA FAILURE TESTS (403)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_invalid_recaptcha_token_rejected(self, mock_client_class):
        """Test 403 when Google returns token validity as False."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=False, reason="EXPIRED"
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid token reason: EXPIRED")

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_action_mismatch_rejected(self, mock_client_class):
        """Test 403 when action in token doesn't match expected action."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(valid=True, action="signup")
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Action mismatch", response.data["error"])

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_low_score_blocked(self, mock_client_class):
        """Test 403 when Google score is below the 0.7 threshold."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="resend-otp", score=0.3
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("reCAPTCHA validation failed.", response.data["error"])

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_internal_server_error_on_google_exception(self, mock_client_class):
        """Test 500 block when Google's SDK raises an unhandled exception."""
        mock_client_instance = mock_client_class.return_value

        # Raise exception when the method is executed
        mock_client_instance.create_assessment.side_effect = Exception(
            "Google service unavailable"
        )

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["error"], "Google service unavailable")

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


class ResendOTPViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("resend-otp")

        self.user = User.objects.create_user(
            email="defaultuser@example.com",
            password="SecurePassword123!",
        )

        prefix = "pre-auth-otp"
        self.cache_obj = {
            "user_id": self.user.id,
            "otp": "123456",
        }

        encrypt_obj = encrypt_data(self.cache_obj)

        self.pre_auth_token_key = f"{prefix}:{encrypt_obj['hashed_key']}"
        cache.set(
            self.pre_auth_token_key,
            encrypt_obj["encrypted_data"],
            timeout=settings.PRE_AUTH_OTP_TTL,
        )

        self.user_lock_key = f"{prefix}-cooldown:{generate_hash_key(self.user.id)}"

        self.pre_auth_token = str(encrypt_obj["token"])
        self.valid_payload = {
            "pre_auth_token": self.pre_auth_token,
            "recaptcha_token": "mock_token_123",
            "recaptcha_version": "v3",
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
        User.objects.all().delete()
        cache.clear()

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="resend-otp", score=0.9
    ):
        """Helper to build a mock Google reCAPTCHA Enterprise response object."""
        mock_response = MagicMock()

        mock_response.token_properties.valid = valid
        mock_response.token_properties.invalid_reason = reason
        mock_response.token_properties.action = action
        mock_response.risk_analysis.score = score

        return mock_response

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_resend_otp_success(self, mock_recaptcha):
        """Test resend OTP with valid pre-auth token. Returns a new pre-auth token."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("pre_auth_token", response.data)
        self.assertNotEqual(response.data["pre_auth_token"], self.pre_auth_token)
        self.assertFalse(cache.get(self.pre_auth_token_key))
        self.assertTrue(cache.get(self.user_lock_key))

    # ==========================================
    # INVALID TESTS (403)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_invalid_pre_auth_token_fails(self, mock_recaptcha):
        """Test that an invalid/malformed pre-auth token returns 403 Forbidden."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        invalid_payload = {
            "pre_auth_token": "completely_invalid_or_expired_token",
            "recaptcha_token": "mock_token_123",
            "recaptcha_version": "v3",
        }

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid Token")

    # ==========================================
    # THROTTLING & RATE LIMIT WORKFLOW TESTS (429)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_otp_cooldown_throttle_returns_429(self, mock_recaptcha):
        """Test that OTPCooldownThrottle blocks a rapid subsequent login attempt with a custom 429 message."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        cache.set(self.user_lock_key, True, timeout=settings.OTP_COOLDOWN_TTL)

        with patch("django.core.cache.cache.ttl", return_value=45, create=True):
            response = self.client.post(
                self.url, self.valid_payload, format="json", **self.headers
            )

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("error", response.data)
        self.assertEqual(
            response.data["error"],
            "Please wait 45 seconds before requesting another OTP.",
        )
        self.assertTrue(cache.get(self.user_lock_key))
