"""Test Cases for User"""

import os, io
from django.conf import settings
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image


class UserModelTests(TestCase):
    """Test User Model"""

    def test_creating_default_user_with_email(self):
        """Test Creating a user with an email is successful"""
        email = "test@example.com"
        password = "Django@123"
        user = get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        default_group = Group.objects.get(name="Default")
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertTrue(user.is_active)
        self.assertEqual(user.username, email)  # checking if username signal is working
        self.assertEqual(
            user.is_email_verified, False
        )  # checking if email verified is false
        self.assertEqual(
            user.is_phone_verified, False
        )  # checking if phone verified is false
        self.assertEqual(
            user.failed_login_attempts, 0
        )  # checking if failed login attempts is 0
        self.assertIn(
            default_group, user.groups.all()
        )  # checking if group signal is working

    def test_creating_admin_user_with_email(self):
        """Test Creating a user with an email is successful"""
        email = "test@example.com"
        password = "Django@123"
        user = get_user_model().objects.create_user(
            email=email, password=password, is_staff=True
        )

        admin_group = Group.objects.get(name="Admin")
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertTrue(user.is_active)
        self.assertEqual(user.username, email)  # checking if username signal is working
        self.assertIn(
            admin_group, user.groups.all()
        )  # checking if group signal is working

    def test_create_user_without_valid_email(self):
        """Test Creating a user without a proper email"""
        email = "test"
        password = "Django@123"

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_create_user_without_valid_password(self):
        """Test Creating a user without a proper password"""
        email = "test@example.com"
        password = "testpass"

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_create_user_without_email_password(self):
        """Test Creating a user without email or password"""
        email = ""
        password = ""

        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_create_superuser_with_valid_data(self):
        """Test creating a superuser with valid data"""
        email = "superuser@example.com"
        password = "Superuser@123"

        # Create superuser
        superuser = get_user_model().objects.create_superuser(
            email=email, password=password
        )

        # Check that the superuser was created correctly
        sup_grp = Group.objects.get(name="Superuser")
        self.assertEqual(superuser.email, email)
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)
        self.assertIn(sup_grp, superuser.groups.all())

    def test_create_superuser_without_password(self):
        """Test creating a superuser without password"""
        email = "superuser@example.com"
        password = ""

        with self.assertRaises(ValueError):
            get_user_model().objects.create_superuser(
                email=email,
                password=password,
            )

    def test_create_superuser_without_is_staff(self):
        """Test creating a superuser without is_staff"""
        email = "superuser@example.com"
        password = "Superuser@123"

        with self.assertRaises(ValueError):
            get_user_model().objects.create_superuser(
                email=email,
                password=password,
                is_staff=False,  # Set to false to trigger ValueError
            )

    def test_create_superuser_without_is_superuser(self):
        """Test creating a superuser without is_staff"""
        email = "superuser@example.com"
        password = "Superuser@123"

        with self.assertRaises(ValueError):
            get_user_model().objects.create_superuser(
                email=email,
                password=password,
                is_superuser=False,  # Set to false to trigger ValueError
            )

    def test_user_with_valid_phone_number(self):
        """Test creating a user with a valid phone number"""
        email = "test@example.com"
        password = "Django@123"
        phone_number = "+8801999999999"

        user = get_user_model().objects.create_user(
            email=email, password=password, phone_number=phone_number
        )

        self.assertEqual(user.phone_number, phone_number)

    def test_user_with_invalid_phone_number(self):
        """Test creating a user with an invalid phone number"""
        email = "test@example.com"
        password = "Django@123"
        phone_number = "12345"  # Invalid phone number

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email, password=password, phone_number=phone_number
            )

    def test_creating_user_slug(self):
        """Test creating a user with a slug"""
        email = "test@example.com"
        password = "Django@123"
        slug = "testexamplecom"

        user = get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        self.assertEqual(user.slug, slug)

    def test_user_slug_with_username_assigned(self):
        """Test creating a user with a slug"""
        email = "test@example.com"
        password = "Django@123"
        username = "testuser"
        slug = "testuser"

        user = get_user_model().objects.create_user(
            email=email, password=password, username=username
        )

        self.assertEqual(user.slug, slug)

    def test_user_slug_update_with_username_update(self):
        """Test creating a user with a slug"""
        email = "test@example.com"
        password = "Django@123"
        slug = "testuser"

        user = get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        user.username = "testuser"
        user.save()

        self.assertEqual(user.slug, slug)


class UserModelImageTests(TestCase):
    """Testing Image upload."""

    def setUp(self):
        "Environment Setup"
        # Create a 10x10 black image using Pillow
        black_image = Image.new("RGB", (10, 10), "black")

        # Save the image to BytesIO object
        image_bytes = io.BytesIO()
        black_image.save(image_bytes, format="JPEG")
        image_bytes.seek(0)

        # Create the image
        self.image = SimpleUploadedFile(
            name="test_image.jpg",
            content=image_bytes.read(),
            content_type="image/jpeg",
        )

        # Create the User
        self.user = get_user_model().objects.create_user(
            email="test@example.com",
            password="Django@123",
        )

    def tearDown(self):
        if os.path.exists(self.image_path):
            os.remove(self.image_path)
        self.user.delete()

    def test_user_with_profile_image(self):
        """Test creating a user with a profile image"""
        self.user.profile_img = self.image
        self.user.save()
        self.image_path = os.path.join(settings.MEDIA_ROOT, self.user.profile_img.name)

        self.assertTrue(self.user.profile_img)
        self.assertEqual(self.user.profile_img.name, "profile_images/test_image.jpg")
        self.assertTrue(os.path.exists(self.image_path))
