"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os, threading, time
from django.core.wsgi import get_wsgi_application
from django.utils.timezone import now
from django.contrib.sessions.models import Session
from django.core.cache import cache

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

application = get_wsgi_application()

def cleanup_sessions():
    """Thread function to clean up expired sessions and clear them from cache."""
    while True:
        # Fetch expired sessions from the database
        expired_sessions = Session.objects.filter(expire_date__lt=now())
        count = 0
        for session in expired_sessions:
            session_key = session.session_key  # Get session key before deletion
            
            # Delete from cache (Redis)
            cache_key = f"django.contrib.sessions.cached_db{session_key}"
            cache.delete(cache_key)

            # Delete from database
            session.delete()
            count += 1

        print(f"Deleted {count} expired session(s)")
        # Wait for 24 hours before running again
        time.sleep(86400)

# Start background thread
thread = threading.Thread(target=cleanup_sessions, daemon=True)
thread.start()
