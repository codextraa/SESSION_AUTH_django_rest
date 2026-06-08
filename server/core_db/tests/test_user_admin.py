"""Tests for the Django admin modifications"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model


class AdminSiteTests(TestCase):
    """Tests for Django admin"""

    def setUp(self):
        """Create user and client"""
        self.client = Client()
        self.admin_user = get_user_model().objects.create_superuser(
            email="admin@example.com",
            password="Django@123",
        )
        self.client.force_login(self.admin_user)
        self.user = get_user_model().objects.create_user(
            email="test@example.com", password="Django@123"
        )

    def test_user_list(self):
        """Test that Users are listed on page."""
        # All the users from core_db app
        url = reverse("admin:core_db_user_changelist")
        res = self.client.get(url)

        self.assertEqual(res.status_code, 200)
        self.assertContains(res, self.user.email)

    def test_create_user_from_admin(self):
        """Test Creating a new user form admin interface"""

        url = reverse("admin:core_db_user_add")
        payload = {
            "email": "newuser@example.com",
            "username": "newuser@example.com",
            "slug": "newuserexamplecom",
            "password1": "Django@123",
            "password2": "Django@123",
            "is_active": True,
            "is_staff": False,
        }
        res = self.client.post(url, payload)

        self.assertEqual(res.status_code, 302)
        self.assertTrue(
            get_user_model().objects.filter(email="newuser@example.com").exists()
        )
