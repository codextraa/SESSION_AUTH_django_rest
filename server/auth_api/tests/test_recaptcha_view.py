from django.urls import reverse
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from unittest.mock import MagicMock, patch


@override_settings(
    RECAPTCHA_PROJECT_ID="test-project-id",
    RECAPTCHA_SITE_KEY_V2="test-site-key-v2",
    RECAPTCHA_SITE_KEY_V3="test-site-key-v3",
)
class RecaptchaViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("recaptcha-verify")

        self.valid_payload = {
            "expected_action": "login",
            "recaptcha_token": "valid-mock-token",
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

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="login", score=0.9
    ):
        """Helper to build a mock Google reCAPTCHA Enterprise response object."""
        mock_response = MagicMock()

        mock_response.token_properties.valid = valid
        mock_response.token_properties.invalid_reason = reason
        mock_response.token_properties.action = action
        mock_response.risk_analysis.score = score

        return mock_response

    # ==========================================
    # SUCCESS TESTS
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_successful_recaptcha_validation(self, mock_client_class):
        """Test where reCAPTCHA token is completely valid and score is high."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="login", score=0.9
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"success": "reCAPTCHA validation successful."})

    # ==========================================
    # REQUEST/VALIDATION ERROR TESTS (400)
    # ==========================================

    def test_missing_expected_action(self):
        """Test 400 bad request when expected_action is missing."""
        payload = self.valid_payload.copy()
        del payload["expected_action"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expected_action", response.data)
        self.assertEqual(response.data["expected_action"][0], "Action is required.")

        payload["expected_action"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expected_action", response.data)
        self.assertEqual(response.data["expected_action"][0], "Action is required.")

        payload["expected_action"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expected_action", response.data)
        self.assertEqual(response.data["expected_action"][0], "Action is required.")

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
        self.assertEqual(response.data["user_agent"][0], "Missing User Agent Header.")

    def test_missing_user_ip_header(self):
        """Test 400 bad request when IP headers are missing."""
        headers = self.headers.copy()
        del headers["HTTP_X_REAL_IP"]

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_ip", response.data)
        self.assertEqual(response.data["user_ip"][0], "Missing User IP Address.")

    # ==========================================
    # REQUEST SERIALIZER IP REPLACEMENT (400)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_ip_parsing_with_x_forwarded_for_single(self, mock_client_class):
        """
        Serializer validation passes and extracts a single IP from HTTP_X_FORWARDED_FOR.
        """
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="login", score=0.9
        )
        mock_client_instance.create_assessment.return_value = mock_response

        headers = self.headers.copy()
        del headers["HTTP_X_REAL_IP"]
        headers["HTTP_X_FORWARDED_FOR"] = "172.16.254.1"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertNotIn("user_ip", response.data)

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_ip_parsing_with_x_forwarded_for_comma_chain(self, mock_client_class):
        """
        Serializer split logic should isolate the first IP in an HTTP_X_FORWARDED_FOR proxy chain.
        """
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="login", score=0.9
        )
        mock_client_instance.create_assessment.return_value = mock_response

        headers = self.headers.copy()
        del headers["HTTP_X_REAL_IP"]
        headers["HTTP_X_FORWARDED_FOR"] = "192.168.1.50, 10.0.0.1, 127.0.0.1"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertNotIn("user_ip", response.data)

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
            valid=True, action="login", score=0.3
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("High risk transaction blocked", response.data["error"])

    # ==========================================
    # EXCEPTION HANDLING TESTS (500)
    # ==========================================

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
    # RECAPTCHA FAILURE TESTS (CSRFTOKEN)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_recaptcha_fails_when_csrf_token_is_missing(self, mock_client_class):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="login", score=0.9
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
