from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from django.contrib.auth.models import User
from rest_framework import generics

from urllib.error import HTTPError
from rest_framework_simplejwt.tokens import RefreshToken
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden
from social_django.utils import load_strategy, load_backend

from django.utils import timezone

from .models import Category, Petition
from .serializers import CategoryListSerializer, PetitionListSerializer, PetitionCreateSerializer, PetitionDetailSerializer, UserListSerializer, LogoutSerializer, SocialAuthSerializer

class SocialLoginView(generics.GenericAPIView):
    serializer_class = SocialAuthSerializer
    permission_classes = [permissions.AllowAny]
 
    def post(self, request):
        """Authenticate user through the provider and access_token"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider = serializer.data.get('provider', None)
        strategy = load_strategy(request)
        
        try:
            backend = load_backend(strategy=strategy, name=provider,
            redirect_uri=None)

        except MissingBackend:
            return Response({'error': 'Please provide a valid provider'},
            status=400)
        try:
            if isinstance(backend, BaseOAuth2):
                access_token = serializer.data.get('access_token')
            user = backend.do_auth(access_token)
        except HTTPError as error:
            return Response({
                "error": {
                    "access_token": "Invalid token",
                    "details": str(error)
                }
            }, status=400)
        except AuthTokenError as error:
            return Response({
                "error": "Invalid credentials",
                "details": str(error)
            }, status=400)
        
        try:
            authenticated_user = backend.do_auth(access_token, user=user)
        
        except HTTPError as error:
            return Response({
                "error":"invalid token",
                "details": str(error)
            }, status=400)
        
        except AuthForbidden as error:
            return Response({
                "error":"invalid token",
                "details": str(error)
            }, status=400)

        if authenticated_user and authenticated_user.is_active:
            #generate JWT token
            #login(request, authenticated_user)
            refresh = RefreshToken.for_user(user)
            #customize the response to your needs
            response = {
                "email": authenticated_user.email,
                "username": authenticated_user.username,
                "access": str(refresh.access_token),
                "refresh": str(response)
            }
            return Response(status=200, data=response)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=204)

class CategoryListView(APIView):

    def get(self, request):
        categories = Category.objects.all()
        serializer = CategoryListSerializer(categories, many=True)
        return Response(serializer.data)

class PetitionListView(APIView):

    def get(self, request):
        title = request.GET.get('title', None)
        category = request.GET.get('category', None)
        creator = request.GET.get('creator', None)
        successful = request.GET.get('successful', None)
        
        
        petitions = Petition.objects.all()

        if title is not None:
            petitions = petitions.filter(title__icontains=title)

        if category is not None and category != "" and category !="null":
            petitions = petitions.filter(category = category)

        if creator is not None:
            creator = creator.lower()
            names = dict()
            for user in User.objects.all():
                names[user.get_full_name()] = user.id
            ids = [value for key, value in names.items() if creator in key.lower()]
            petitions = petitions.filter(creator_id__in=ids)

        if successful is not None:
            successful = successful.lower()

            if successful == "true":
                for petition in petitions:
                    if not petition.HasPassed():
                        petitions = petitions.exclude(id = petition.id)
            elif successful == "false":
                for petition in petitions:
                    if not (petition.IsExpired() and not petition.HasPassed()):
                        petitions = petitions.exclude(id = petition.id)          
        
        serializer = PetitionListSerializer(petitions, many=True)
        return Response(serializer.data)


class PetitionCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.data['creator'] = request.user.id
        petition = PetitionCreateSerializer(data=request.data)
        if petition.is_valid():
            obj = petition.save()
        return Response({'id': obj.id}, status=201)

class PetitionDetailView(APIView):

    def get(self, request, pk):
        petition = Petition.objects.get(id=pk)
        serializer = PetitionDetailSerializer(petition)
        return Response(serializer.data)

class VoteSubmitView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        petition = Petition.objects.get(id=pk)
        petition.voters.add(request.user)
        petition.save()
        return Response(status=201)

class UserListView(APIView):

    def get(self, request):
        users = User.objects.all()
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data)

class StatisticsView(APIView):

    def get(self, request):
        pet_num = Petition.objects.count()
        vote_num = 0
        for petition in Petition.objects.all():
            vote_num += petition.VoteCount()

        return Response({'petitions_number': pet_num, 'vote_number' : vote_num})

class VotedUsersView(APIView):

    def get(self, request, pk):
        petition = Petition.objects.get(id=pk)
        serializer = UserListSerializer(petition.voters, many=True)
        return Response(serializer.data)
