from django.urls import path
from . import views

urlpatterns = [
    path("get-csrf-token/", views.CSRFTokenView.as_view(), name="csrf-token"),
]
