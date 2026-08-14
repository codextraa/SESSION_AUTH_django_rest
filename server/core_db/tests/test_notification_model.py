from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from core_db.models import Notification

User = get_user_model()


class NotificationModelTests(TestCase):
    def setUp(self):
        """Set up test data for notification model tests."""
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="Testpassword@123",
        )

    def test_notification_creation_success(self):
        """Test successful creation of a Notification object with explicit data."""
        data_payload = {"url": "/orders/101", "type": "ORDER_SUCCESS"}
        notification = Notification.objects.create(
            user=self.user,
            title="Order Shipped",
            body="Your order #101 has been shipped.",
            data=data_payload,
        )

        self.assertEqual(notification.user, self.user)
        self.assertEqual(notification.title, "Order Shipped")
        self.assertEqual(notification.body, "Your order #101 has been shipped.")
        self.assertEqual(notification.data, data_payload)
        self.assertFalse(notification.is_read)
        self.assertIsNotNone(notification.created_at)

    def test_notification_default_values(self):
        """Test that default values for is_read and data are correctly set."""
        notification = Notification.objects.create(
            user=self.user,
            title="Default Test",
            body="Testing default fields.",
        )

        self.assertEqual(notification.data, {})
        self.assertFalse(notification.is_read)

    def test_ordering_by_created_at_descending(self):
        """Test that notifications are ordered by created_at in descending order (newest first)."""
        first_notif = Notification.objects.create(
            user=self.user,
            title="First Notification",
            body="First body.",
        )
        second_notif = Notification.objects.create(
            user=self.user,
            title="Second Notification",
            body="Second body.",
        )

        notifications = list(Notification.objects.all())
        self.assertEqual(notifications, [second_notif, first_notif])

    def test_user_foreign_key_cascade_delete(self):
        """Test that deleting a user automatically deletes associated notifications."""
        Notification.objects.create(
            user=self.user,
            title="Cascade Test",
            body="Testing foreign key cascade deletion.",
        )
        self.assertEqual(Notification.objects.count(), 1)

        self.user.delete()
        self.assertEqual(Notification.objects.count(), 0)

    def test_notification_without_user_raises_error(self):
        """Test that creating a Notification without a user raises IntegrityError."""
        with self.assertRaises(IntegrityError):
            Notification.objects.create(
                user=None,
                title="No User Test",
                body="This should fail.",
            )

    def test_notification_without_title_raises_error(self):
        """Test that creating a Notification with title=None raises IntegrityError."""
        with self.assertRaises(IntegrityError):
            Notification.objects.create(
                user=self.user,
                title=None,
                body="Body without title.",
            )

    def test_notification_without_body_raises_error(self):
        """Test that creating a Notification with body=None raises IntegrityError."""
        with self.assertRaises(IntegrityError):
            Notification.objects.create(
                user=self.user,
                title="Title without body",
                body=None,
            )

    def test_mark_notification_as_read(self):
        """Test updating the is_read status to True."""
        notification = Notification.objects.create(
            user=self.user,
            title="Unread Alert",
            body="Please read this alert.",
        )
        self.assertFalse(notification.is_read)

        notification.is_read = True
        notification.save()
        notification.refresh_from_db()

        self.assertTrue(notification.is_read)
