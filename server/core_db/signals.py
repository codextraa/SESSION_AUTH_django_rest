"""Signals used before or after saving a model"""

from django.db.models.signals import pre_save, post_save
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.dispatch import receiver
from django.utils.text import slugify
from .models import User
from .utils import generate_random_username

User = get_user_model()


@receiver(pre_save, sender=User)
def set_user_username(sender, instance, **kwargs):  # pylint: disable=unused-argument
    """Set unique username if not provided"""
    if not instance.username:
        username = generate_random_username()

        while User.objects.filter(username=username).exists():
            username = generate_random_username()

        instance.username = username


@receiver(post_save, sender=User)
def save_user_slug(
    sender, instance, created, **kwargs
):  # pylint: disable=unused-argument
    """Create slug for user using username"""
    if created or (slugify(instance.username) != instance.slug):
        instance.slug = slugify(instance.username)
        instance.save()


@receiver(post_save, sender=User)
def set_user_default_group(
    sender, instance, created, **kwargs
):  # pylint: disable=unused-argument
    if created and instance.pk:
        if instance.is_superuser:
            instance.profile_img = "profile_images/default_profile.jpg"
            admin_group, _ = Group.objects.get_or_create(name="Superuser")
            instance.groups.add(admin_group)
            instance.save()
        elif instance.is_staff:
            admin_group, _ = Group.objects.get_or_create(name="Admin")
            instance.groups.add(admin_group)
        else:
            default_group, _ = Group.objects.get_or_create(name="Default")
            instance.groups.add(default_group)
