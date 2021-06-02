from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from djoser.serializers import UserCreateSerializer

from .models import Category, Petition

class UserRegisterSerializer(UserCreateSerializer):

    class Meta(UserCreateSerializer.Meta):
        fields = ["id", "username", "password", "first_name", "last_name", "email"]


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad token')

class CategoryListSerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = "__all__"

class PetitionListSerializer(serializers.ModelSerializer):
    category = serializers.SlugRelatedField(slug_field="name", read_only=True)
    creator_name = serializers.SerializerMethodField()
    datetime_expires = serializers.SerializerMethodField()
    vote_count = serializers.SerializerMethodField()

    def get_creator_name(self, obj):
        return f"{obj.creator.first_name} {obj.creator.last_name}"

    def get_datetime_expires(self, obj):
        return obj.DateExpires()

    def get_vote_count(self, obj):
        return obj.VoteCount()

    class Meta:
        model = Petition
        exclude = ('text', 'voters', 'creator')

class PetitionDetailSerializer(serializers.ModelSerializer):
    category = serializers.SlugRelatedField(slug_field="name", read_only=True)
    creator_name = serializers.SerializerMethodField()
    datetime_expires = serializers.SerializerMethodField()
    vote_count = serializers.SerializerMethodField()

    def get_creator_name(self, obj):
        return obj.creator.get_full_name()

    def get_datetime_expires(self, obj):
        return obj.DateExpires()

    def get_vote_count(self, obj):
        return obj.VoteCount()

    class Meta:
        model = Petition
        exclude = ('voters',)

class PetitionCreateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Petition
        exclude = ('datetime_created', 'voters')

class UserListSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    def get_full_name(self, obj):
        return obj.get_full_name()

    class Meta:
        model = User
        fields = ['id', 'full_name']

class SocialAuthSerializer(serializers.Serializer):
    provider = serializers.CharField(max_length=255, required=True)
    access_token = serializers.CharField(max_length=4096, required=True, trim_whitespace=True)