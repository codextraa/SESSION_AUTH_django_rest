import re
from django.contrib.auth import get_user_model
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field


def validate_password(password):
    """Password Validation"""
    errors = {}
    
    if len(password) < 8:
        errors['short'] = 'Password must be at least 8 characters long.'
        
    if not re.search(r"[a-z]", password):
        errors['lower'] = 'Password must contain at least one lowercase letter.'
        
    if not re.search(r"[A-Z]", password):
        errors['upper'] = 'Password must contain at least one uppercase letter.'
        
    if not re.search(r"[0-9]", password):
        errors['number'] = 'Password must contain at least one number.'
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors['special'] = 'Password must contain at least one special character.'
        
    return errors
    
class PasswordResetSerializer(serializers.ModelSerializer):
    """Password Reset Serializer"""
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'password')
        read_only_fields = ('id',)
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'} 
            }
        }
        
    def validate(self, attrs):
        """Validate all data"""
        password = attrs.get('password')
        if password:
            validate_password(password)
            
        return super().validate(attrs)
        
    def update(self, instance, validated_data):
        """Update and return an existing user"""
        password = validated_data.pop("password", None)
        
        if not password:
            raise serializers.ValidationError("Password is required.")
        
        if instance.check_password(password):
            raise serializers.ValidationError("New password cannot be the same as the old password.")
        
        errors = validate_password(password)
        if errors:
            raise serializers.ValidationError(errors)
        
        instance.set_password(password)
        instance.save()

        return instance

class UserListSerializer(serializers.ModelSerializer):
    """List User Serializer"""

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'username', 'is_active', 'is_staff')
        read_only_fields = ('id', 'email', 'username', 'is_active', 'is_staff')
        
class UserActionSerializer(serializers.ModelSerializer):
    """Action User Serializer"""

    class Meta:
        model = get_user_model()
        fields = ('id',)
        read_only_fields = ('id',)

class UserSerializer(serializers.ModelSerializer):
    """User Serializer"""
    profile_img = serializers.SerializerMethodField()
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'password', 'username', 'first_name', 
                  'last_name', 'phone_number', 'profile_img', 'slug', 
                  'is_active', 'is_staff', 'is_superuser', 'is_email_verified',
                  'is_phone_verified')
        read_only_fields = ('id', 'is_superuser', 'is_email_verified', 
                            'is_phone_verified')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'} 
            }
        }
        
    def validate(self, attrs):
        """Validate all data"""
        password = attrs.get('password')
        
        if password:
            errors = validate_password(password)
            if errors:
                raise serializers.ValidationError({'password': errors})
            
        username = attrs.get('username')
        if username:
            if len(username) < 6:
                raise serializers.ValidationError({'username': 'Username must be at least 6 characters long.'})
        
        attrs = super().validate(attrs)
        
        if attrs.get('first_name'):
            attrs['first_name'] = attrs['first_name'].title()
        if attrs.get('last_name'):
            attrs['last_name'] = attrs['last_name'].title()
        
        return attrs
    
    @extend_schema_field(serializers.CharField())
    def get_profile_img(self, obj):
        if obj.profile_img:
            if obj.profile_img.name.startswith("http"):
                return obj.profile_img.name
            
            return obj.profile_img.url
    
    def create(self, validated_data):
        # Need to check this
        """Create and return a user with encrypted password."""
        profile_img = validated_data.pop('profile_img', None)
        
        if not profile_img:
            """Set default profile image if not provided"""
            default_image_path = 'profile_images/default_profile.jpg'
            validated_data['profile_img'] = default_image_path

        return get_user_model().objects.create_user(**validated_data)
    
    def update(self, instance, validated_data):
        """Update and return an existing user"""
        if validated_data.get('phone_number') != instance.phone_number:
            validated_data['is_phone_verified'] = False
                
        return super().update(instance, validated_data)
        
    
class UserImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'profile_img')
        read_only_fields = ('id',)

    def validate_profile_img(self, value):
        """Validate profile image"""
        if not value:
            raise serializers.ValidationError('Profile image is required.')
        
        errors = {}
        max_size = 2 * 1024 * 1024 # 2MB
        valid_file_types = ['image/jpeg', 'image/png'] # valid image types
        
        if value.size > max_size:
            errors['size'] = 'Profile image size should not exceed 2MB.'

        if hasattr(value, 'content_type') and value.content_type not in valid_file_types:
            errors['type'] = 'Profile image type should be JPEG, PNG'
            
        if errors:
            raise serializers.ValidationError(errors)

        return value

class RecaptchaSerializer(serializers.Serializer):
    recaptcha_token = serializers.CharField(required=True)    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)
    
class ResendOtpSerializer(serializers.Serializer):
    user_id = serializers.CharField(required=True)

class TokenRequestSerializer(serializers.Serializer):
    user_id = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)
    
class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)
    
class PhoneVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)
    
class VerificationThroughEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
class InputPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    c_password = serializers.CharField(required=True)
    
class CreateUserSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)
    c_password = serializers.CharField(required=True)
    username = serializers.CharField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    phone_number = serializers.CharField(required=False)
    is_staff = serializers.BooleanField(required=False, default=False)
    
class UpdateUserSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    username = serializers.CharField(required=False)
    phone_number = serializers.CharField(required=False)
    
class SocialOAuthSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    provider = serializers.CharField(required=True)
