import os
import json
import logging
import firebase_admin
from server.tasks import dispatch_fcm_notification
from core_db.models import Notification

logger = logging.getLogger(__name__)


def initialize_firebase():
    """
    Initializes the Firebase Admin SDK if not already initialized.
    """
    if firebase_admin._apps:
        return

    try:
        cred = os.getenv("GCP_SERVICE_ACCOUNT_JSON")

        if cred:
            raw_json = os.getenv("GCP_SERVICE_ACCOUNT_JSON")
            cred_dict = json.loads(raw_json)
            cred = firebase_admin.credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin SDK initialized using Google Credentials")
        else:
            firebase_admin.initialize_app()
            logger.info("Firebase Admin SDK initialized using Default Credentials.")
    except Exception as exc:
        logger.error("Failed to initialize Firebase Admin SDK: %s", exc)
        raise exc


def create_notification(user, title, body, data=None):
    """
    Creates a Notification DB record sequentially.
    Triggers FCM push via Celery asynchronously.
    Returns True on success, or None silently on failure.
    """
    initialize_firebase()

    try:
        notification = Notification.objects.create(
            user=user, title=title, body=body, data=data or {}
        )

        payload_data = dict(data or {})
        payload_data["notification_id"] = str(notification.id)

        dispatch_fcm_notification.delay(
            user_id=user.id, title=title, body=body, data=payload_data
        )

        return True
    except Exception as e:  # pylint: disable=W0718
        logger.error(
            f"Failed to create notification for user {getattr(user, 'id', None)}: {str(e)}"
        )
        return None
