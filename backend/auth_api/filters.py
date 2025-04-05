import django_filters
from django.db.models import Q
from django.contrib.auth import get_user_model


class UserFilter(django_filters.FilterSet):
    """User Filter"""

    search = django_filters.CharFilter(method="filter_email_or_username")
    is_active = django_filters.BooleanFilter()
    group = django_filters.CharFilter(method="filter_by_group")

    class Meta:
        model = get_user_model()
        fields = ("search", "is_active", "group")

    def filter_email_or_username(
        self, queryset, name, value
    ):  # pylint: disable=unused-argument
        """Filter users where email OR username contains the search value."""
        return queryset.filter(Q(email__icontains=value) | Q(username__icontains=value))

    def filter_by_group(self, queryset, name, value):  # pylint: disable=unused-argument
        """FIlter users by group name."""
        return queryset.filter(groups__name__iexact=value.strip())
