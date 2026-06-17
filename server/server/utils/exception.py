from rest_framework.exceptions import APIException
from rest_framework import status


class ForbiddenValidationError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Permission denied."
    default_code = "permission_denied"
