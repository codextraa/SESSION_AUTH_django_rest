"""Test Cases for User"""

import os, io
from django.conf import settings
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
from server.validators import PasswordComplexityValidator


class UserModelTests(TestCase):
    """Test User Model"""

    def setUp(self):
        """Environment Setup"""
        self.validator = PasswordComplexityValidator()

    def test_creating_default_user_with_email(self):
        """Test Creating a user with an email is successful"""
        email = "test@example.com"
        password = "Django@123"
        user = get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        default_group, created = Group.objects.get_or_create(name="Default")
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
        self.assertIn(
            default_group, user.groups.all()
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

    def test_create_user_with_duplicate_email(self):
        """Test Creating a user with duplicate email"""
        email = "test@example.com"
        password = "Django@123"

        get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_create_user_with_different_cased_email(self):
        """Test Creating a user with different cased email"""
        email = "test@example.com"
        password = "Django@123"

        get_user_model().objects.create_user(
            email=email,
            password=password,
        )

        email = "Test@example.com"
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

    def test_creating_admin_user_with_email(self):
        """Test Creating an admin with an email is successful"""
        email = "staff@example.com"
        password = "Django@123"
        user = get_user_model().objects.create_user(
            email=email, password=password, is_staff=True
        )

        admin_group, created = Group.objects.get_or_create(name="Admin")
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertTrue(user.is_active)
        self.assertEqual(user.username, email)  # checking if username signal is working
        self.assertIn(
            admin_group, user.groups.all()
        )  # checking if group signal is working

    def test_creating_admin_without_password(self):
        """Test creating an admin without password"""
        email = "admin@example.com"
        password = ""

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
                is_staff=True,
            )

    def test_creating_admin_with_is_staff_false(self):
        """Test creating an admin with is_staff false results in normal user"""
        email = "admin@example.com"
        password = "Django@123"

        user = get_user_model().objects.create_user(
            email=email,
            password=password,
            is_staff=False,
        )

        default_group, created = Group.objects.get_or_create(name="Default")
        self.assertEqual(user.is_staff, False)
        self.assertIn(default_group, user.groups.all())

    def test_create_superuser_with_valid_data(self):
        """Test creating a superuser with valid data"""
        email = "superuser@example.com"
        password = "Django@123"

        # Create superuser
        superuser = get_user_model().objects.create_superuser(
            email=email, password=password
        )

        # Check that the superuser was created correctly
        sup_grp, created = Group.objects.get_or_create(name="Superuser")
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

    # --- Unit Tests for Slug ---

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

    # --- Unit Tests for PasswordComplexityValidator Class ---

    def test_validator_accepts_valid_password(self):
        """Test validator accepts password meeting all criteria"""
        # Should not raise any exceptions
        self.validator.validate("Valid@123")

    def test_validator_fails_short_password(self):
        """Test validator catches passwords shorter than 8 characters"""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate("Val@1")
        self.assertIn(
            "Password must be at least 8 characters.", context.exception.messages
        )

    def test_validator_fails_missing_uppercase(self):
        """Test validator catches passwords missing an uppercase letter"""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate("valid@123")
        self.assertIn(
            "Password must contain at least one uppercase letter.",
            context.exception.messages,
        )

    def test_validator_fails_missing_lowercase(self):
        """Test validator catches passwords missing a lowercase letter"""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate("VALID@123")
        self.assertIn(
            "Password must contain at least one lowercase letter.",
            context.exception.messages,
        )

    def test_validator_fails_missing_number(self):
        """Test validator catches passwords missing a numerical digit"""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate("Valid@abc")
        self.assertIn(
            "Password must contain at least one number.", context.exception.messages
        )

    def test_validator_fails_missing_special_character(self):
        """Test validator catches passwords missing a special symbol"""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate("Valid1234")
        self.assertIn(
            "Password must contain at least one special character.",
            context.exception.messages,
        )

    def test_validator_returns_correct_help_text(self):
        """Test validator provides the correct text layout for Django Admin/Forms"""
        expected_text = (
            "Your password must contain at least 8 characters, "
            "including 1 uppercase letter, 1 lowercase letter, 1 number, "
            "and 1 special character."
        )
        self.assertEqual(self.validator.get_help_text(), expected_text)

    # --- Integration Tests through Core Django Security Filters ---

    def test_user_creation_fails_with_simialar_password(self):
        """Test integration catches similar passwords"""
        # 'password' passes complexity criteria, but should be blocked
        # by django.contrib.auth.password_validation.UserAttributeSimilarityValidator
        email = "similarity_pass@example.com"
        password = "password"

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_user_creation_fails_built_in_common_password(self):
        """Test integration catches generic/common passwords defined by Django"""
        # 'password123' passes complexity criteria, but should be blocked
        # by django.contrib.auth.password_validation.CommonPasswordValidator
        email = "common_pass@example.com"
        password = "abcd1234"

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )

    def test_user_creation_fails_built_in_numeric_password(self):
        """Test integration catches purely numeric strings"""
        # Blocked by django.contrib.auth.password_validation.NumericPasswordValidator
        email = "numeric_pass@example.com"
        password = "123456789012345"

        with self.assertRaises(ValidationError):
            get_user_model().objects.create_user(
                email=email,
                password=password,
            )


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
