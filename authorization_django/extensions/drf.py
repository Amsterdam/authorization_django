import sys

from django.conf import settings
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission
from rest_framework.request import Request

from authorization_django.config import get_settings

# Auto-register a schema extension when the project uses drf-spectacular
if "drf_spectacular" in settings.INSTALLED_APPS or "drf_spectacular" in sys.modules:
    import authorization_django.extensions.scheme  # noqa: F401


class JWTAuthentication(BaseAuthentication):
    """Bridge the JWT authentication from authorization-django to DRF views.
    This can be used in the ``authentication_classes`` for APIView.
    """

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


class HasTokenScopes(BasePermission):
    """Permission check, wrapped in a DRF permissions adapter.
    This can be used in the ``permission_classes`` for APIView.
    """

    message = "Required scopes not given in token."

    def __init__(self, *needed_scopes):
        self.needed_scopes = frozenset(needed_scopes or get_settings()["MIN_SCOPE"])

    def has_permission(self, request, view):
        """Check whether the user has all required scopes"""
        # This essentially does what request.is_authorized_for() does, without the logging.
        # In this scenario it's not clear whether this is the only permission check,
        # so falsely logging that access is granted is a bit premature.
        return get_settings()["ALWAYS_OK"] or set(request.get_token_scopes).issuperset(
            self.needed_scopes
        )

    def has_object_permission(self, request, view, obj):
        """Object-level permission is currently identical to view-level permission."""
        return self.has_permission(request, view)
