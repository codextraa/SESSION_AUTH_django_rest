from rest_framework import serializers
from core_db.models import FCMToken


class FCMTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = FCMToken
        fields = ("id", "user", "token", "created_at", "updated_at")
        read_only_fields = ("id", "user", "created_at", "updated_at")
        extra_kwargs = {
            "token": {
                "validators": []
            }  # Remove default unique validator to handle update_or_create logic manually
        }

    def create(self, validated_data):
        token_str = validated_data.get("token")
        user = self.context["user"]

        token_obj, _ = FCMToken.objects.update_or_create(
            token=token_str, defaults={"user": user}
        )

        return token_obj
