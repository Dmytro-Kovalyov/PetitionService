from django.conf import settings
from oauth2client import client, crypt
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import (
    TokenAuthentication, SessionAuthentication)


class GoogleAuthentication(TokenAuthentication):
    def __init__(self, *args, **kwargs):
        self.request = None
        super().__init__(*args, **kwargs)

    def authenticate(self, request):
        self.request = request
        return super().authenticate(request)

    def authenticate_credentials(self, token):
        User = get_user_model()

        _token = self.request.session.get('token')
        email = self.request.session.get('email')
        name = ""
        idinfo = {}
        if token != _token:
            try:
                idinfo = client.verify_id_token(
                    token, settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY)
                auth_domains = ['accounts.google.com',
                                'https://accounts.google.com']
                if idinfo['iss'] not in auth_domains:
                    raise crypt.AppIdentityError("Wrong issuer.")

        email = idinfo['email']
        print(idinfo)
        name = idinfo['name'].split()
        user = {}

        try:
            user = User.objects.get(email=email, username=email.split('@')[0])
        except:
            if len(name) == 1:
                user = User.objects.create(email=email, username=email.split('@')[0], first_name=name[0])
            else:
                user = User.objects.create(email=email, username=email.split('@')[0], first_name=name[0], last_name=name[1])


        self.request.session['token'] = token
        self.request.session['email'] = email
        return (user, token)


class CustomSessionAuthentication(SessionAuthentication):
    def authenticate_header(self, request):
        return 'OAuth realm="api"'