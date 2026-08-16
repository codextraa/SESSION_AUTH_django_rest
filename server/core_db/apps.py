from django.apps import AppConfig


class CoreDbConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core_db"

    def ready(self):
        import core_db.signals
        from server.utils.firebase import initialize_firebase

        initialize_firebase()
