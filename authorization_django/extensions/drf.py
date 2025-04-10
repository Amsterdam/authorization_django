from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request

import authorization_django.extensions.scheme  # noqa: F401


class JWTAuthentication(BaseAuthentication):
    """Bridge the JWT authentication from authorization-django to DRF views."""

    www_authenticate_realm = "api"

    def authenticate(self, request):
        """Tell REST Framework that we do have an authentication header.
        This makes sure a HTTP 403 (Forbidden) response is given instead of 401 (Unauthorized).
        """
        if not request.get_token_claims:
            msg = (
                "The request requires user authentication. The response MUST include a "
                "WWW-Authenticate header field (section 14.47) containing a challenge "
                "applicable to the requested resource."
            )
            raise exceptions.NotAuthenticated(msg)
        # Is authenticated, fill "request.auth" and "request.authenticators".
        return None, request.get_token_claims

    def authenticate_header(self, request: Request) -> str:
        return f'Bearer realm="{self.www_authenticate_realm}"'
