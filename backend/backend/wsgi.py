"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os
import threading
import time
from django.core.wsgi import get_wsgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

application = get_wsgi_application()

# pylint: disable=C0413
from django.utils.timezone import now
from django.contrib.sessions.models import Session
from django.core.cache import cache

stop_event = threading.Event()  # Allows graceful stopping of thread


def cleanup_sessions():
    """Thread function to clean up expired sessions from database and cache."""
    while not stop_event.is_set():
        try:
            # Fetch and delete expired sessions from DB in bulk
            expired_sessions = Session.objects.filter(expire_date__lt=now())
            count = expired_sessions.count()

            for session in expired_sessions:
                session_key = session.session_key

                # Construct the correct cache key
                cache_key = f"django.contrib.sessions.cached_db{session_key}"
                cache.delete(cache_key)  # Delete session from cache

            expired_sessions.delete()  # Bulk delete all expired sessions

            print(f"Deleted {count} expired session(s)")

        except Exception as e:  # pylint: disable=W0718
            print(f"Session cleanup error: {e}")

        # Wait for 6 hour before running again
        time.sleep(21600)


# Start background thread
thread = threading.Thread(target=cleanup_sessions, daemon=True)
thread.start()
