import logging
from firebase_admin import messaging
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.contrib.auth import get_user_model
from core_db.models import FCMToken

logger = logging.getLogger(__name__)

User = get_user_model()


@shared_task(bind=True, max_retries=3)
def dispatch_fcm_notification(self, user_id, title, body, data=None):
    """
    Directly sends FCM push notifications to all active device tokens of a user.
    Handles automatic cleanup of expired/invalid registration tokens.
    """
    try:
        user = User.objects.get(id=user_id)

        tokens = list(
            FCMToken.objects.filter(user=user).values_list("token", flat=True)
        )

        if not tokens:
            return {
                "status": "success",
                "fcm_delivered_devices": 0,
            }

        # FCM object to string conversion
        string_data = {k: str(v) for k, v in (data or {}).items()}

        message = messaging.MulticastMessage(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data=string_data,
            tokens=tokens,
        )

        response = messaging.send_each_for_multicast(message)

        # Cleanup invalid/unregistered tokens in responses
        tokens_to_delete = []
        for idx, resp in enumerate(response.responses):
            if not resp.success and resp.exception:
                if isinstance(
                    resp.exception,
                    (messaging.UnregisteredError, messaging.SenderIdMismatchError),
                ):
                    tokens_to_delete.append(tokens[idx])
                elif getattr(resp.exception, "code", None) in [
                    "UNREGISTERED",
                    "INVALID_ARGUMENT",
                ]:
                    tokens_to_delete.append(tokens[idx])

        if tokens_to_delete:
            FCMToken.objects.filter(token__in=tokens_to_delete).delete()

        return {
            "status": "success",
            "fcm_delivered_devices": response.success_count,
        }
    except User.DoesNotExist:
        logger.error("FCM Multicast error for user %s: User not found", user_id)
        return {"status": "failed", "reason": "User not found"}
    except Exception as exc:  # pylint: disable=W0718
        logger.warning(
            "Attempt %s/%s failed. FCM Multicast error: %s. Retrying again",
            self.request.retries,
            self.max_retries,
            exc,
        )
        try:
            raise self.retry(exc=exc, countdown=5)
        except MaxRetriesExceededError as err:
            logger.error("FCM Multicast error for user %s: %s", user_id, str(err))

    return None
