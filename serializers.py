from django.contrib.auth.models import User
from .models import Photo
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ['id', 'username', 'phone', 'email', 'password', 'date_joined']

class PhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Photo
        fields = ['id', 'image', 'category', 'order', 'show_in_public', 'created_at']
        read_only_fields = ['id', 'created_at']