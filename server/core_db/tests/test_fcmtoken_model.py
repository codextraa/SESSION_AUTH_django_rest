from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from core_db.models import FCMToken

User = get_user_model()


class FCMTokenModelTests(TestCase):
    def setUp(self):
        """Set up test user data."""
        self.user = User.objects.create_user(
            username="fcmuser",
            email="fcmuser@example.com",
            password="Securepassword@123",
        )

    def test_fcm_token_creation_success(self):
        """Test successful creation of an FCMToken object."""
        sample_token = "fcm_token_sample_string_1234567890_abc"
        fcm_token = FCMToken.objects.create(
            user=self.user,
            token=sample_token,
        )

        self.assertEqual(fcm_token.user, self.user)
        self.assertEqual(fcm_token.token, sample_token)
        self.assertIsNotNone(fcm_token.created_at)
        self.assertIsNotNone(fcm_token.updated_at)

    def test_duplicate_token_raises_integrity_error(self):
        """Test that token uniqueness constraint prevents saving duplicate tokens."""
        sample_token = "unique_fcm_token_string_999"
        FCMToken.objects.create(user=self.user, token=sample_token)

        # Attempt to create another FCMToken with the exact same token string
        another_user = User.objects.create_user(
            username="otheruser",
            email="otheruser@example.com",
            password="Securepassword@123",
        )
        with self.assertRaises(ValidationError):
            FCMToken.objects.create(user=another_user, token=sample_token)

    def test_user_can_have_multiple_tokens(self):
        """Test that a single user can have multiple active FCM tokens (e.g., multiple devices)."""
        token1 = FCMToken.objects.create(user=self.user, token="device_token_1")
        token2 = FCMToken.objects.create(user=self.user, token="device_token_2")

        self.assertEqual(self.user.fcm_tokens.count(), 2)
        self.assertIn(token1, self.user.fcm_tokens.all())
        self.assertIn(token2, self.user.fcm_tokens.all())

    def test_ordering_by_updated_at_descending(self):
        """Test that tokens are ordered by updated_at descending (most recently updated first)."""
        token1 = FCMToken.objects.create(user=self.user, token="token_device_alpha")
        token2 = FCMToken.objects.create(user=self.user, token="token_device_beta")

        # Trigger update on token1 to bump its updated_at timestamp
        token1.save()

        tokens = list(FCMToken.objects.all())
        self.assertEqual(tokens, [token1, token2])

    def test_user_cascade_deletion(self):
        """Test that deleting a user automatically deletes all associated FCM tokens."""
        FCMToken.objects.create(user=self.user, token="token_to_cascade_delete")
        self.assertEqual(FCMToken.objects.count(), 1)

        self.user.delete()
        self.assertEqual(FCMToken.objects.count(), 0)

    def test_creation_without_user_raises_error(self):
        """Test that creating an FCMToken without a user raises IntegrityError."""
        with self.assertRaises(ValidationError):
            FCMToken.objects.create(user=None, token="orphaned_token_123")

    def test_creation_without_token_raises_error(self):
        """Test that creating an FCMToken with token=None raises IntegrityError."""
        with self.assertRaises(ValidationError):
            FCMToken.objects.create(user=self.user, token=None)
