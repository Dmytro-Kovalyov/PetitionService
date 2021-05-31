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
        first_name = ""
        last_name = ""

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
                first_name = idinfo['given_name']
                last_name = idinfo['name']

            except crypt.AppIdentityError:
                raise AuthenticationFailed('Invalid token.')

        if first_name == last_name:
            last_name = ""
        user, created = User.objects.get_or_create(email=email, username=email.split('@')[0], first_name=first_name, last_name=last_name)
        self.request.session['token'] = token
        self.request.session['email'] = email
        return (user, token)


class CustomSessionAuthentication(SessionAuthentication):
    def authenticate_header(self, request):
        return 'OAuth realm="api"'