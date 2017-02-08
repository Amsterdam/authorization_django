"""
:see: http://www.django-rest-framework.org/api-guide/authentication/#custom-authentication
"""
from django.conf import settings
from rest_framework import authentication
from rest_framework import exceptions
import jwt
from authz import levels


class TokenAuthorization(authentication.BaseAuthentication):

    def authenticate(self, request):
        # NOTE: get_authorization_header returns a byte string
        auth = authentication.get_authorization_header(request)

        if not auth:
            # TODO: crash if there's no token
            return ({'authz': levels.LEVEL_DEFAULT}, None)

        try:
            prefix, token = auth.split()
        except ValueError:
            raise exceptions.AuthenticationFailed(
                'Invalid Authorization header format; should be "JWT [token]"')

        # The below is not necessary; the prefix does not need to be enforced
        # TODO: fix with frontend
        if prefix != b'JWT':
            raise exceptions.AuthenticationFailed('Must use the JWT prefix')

        try:
            decoded = jwt.decode(
                token,
                key=settings.JWT_SECRET_KEY,
                algorithms=(settings.JWT_ALGORITHM,)
            )
        except jwt.InvalidTokenError as e:
            raise exceptions.AuthenticationFailed() from e

        return (decoded, token)
