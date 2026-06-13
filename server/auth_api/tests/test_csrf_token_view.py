from datetime import datetime, timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase


class CSRFTokenViewTests(APITestCase):

    def setUp(self):
        """Initialize the URL for the CSRF token endpoint."""
        self.url = reverse("csrf-token")

    def test_get_csrf_token_success_status_code(self):
        """Test that a GET request returns a 200 OK status code."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_csrf_token_returns_expected_keys(self):
        """Test that the response contains the exact keys defined in the view logic."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIn("csrf_token", data)
        self.assertIn("csrf_token_expiry", data)

    def test_get_csrf_token_values_are_valid(self):
        """Test that the returned token is a non-empty string and expiry is a valid ISO timestamp."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIsInstance(data["csrf_token"], str)
        self.assertTrue(len(data["csrf_token"]) > 0)

        try:
            expiry_dt = datetime.fromisoformat(
                data["csrf_token_expiry"].replace("Z", "+00:00")
            )
        except ValueError:
            self.fail("csrf_token_expiry is not a valid ISO 8601 string")

        self.assertTrue(expiry_dt > datetime.now(timezone.utc))

    def test_csrf_cookie_is_set_in_response(self):
        """Test that Django actually sets the 'csrftoken' cookie in the response headers."""
        response = self.client.get(self.url)
        self.assertIn("csrftoken", response.cookies)

    def test_invalid_methods_are_disallowed(self):
        """Test that methods other than GET (like POST, PUT, DELETE) return 405 Method Not Allowed."""
        invalid_methods = ["post", "put", "patch", "delete"]

        for method in invalid_methods:
            client_method = getattr(self.client, method)
            response = client_method(self.url)
            self.assertEqual(
                response.status_code,
                status.HTTP_405_METHOD_NOT_ALLOWED,
                msg=f"Method {method.upper()} should not be allowed.",
            )
