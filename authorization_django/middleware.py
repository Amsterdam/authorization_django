"""
authorization_django.middleware
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import json
import logging
from time import time

from django import http
from jwcrypto.common import JWException
from jwcrypto.jwt import JWT, JWTExpired, JWTMissingKey

from .config import get_settings
from .jwks import check_update_keyset, get_keyset

logger = logging.getLogger(__name__)


class _AuthorizationHeaderError(Exception):

    def __init__(self, response):
        self.response = response


def authorization_middleware(get_response):
    """Old style middleware function, for backwards compatibility."""
    return AuthorizationMiddleware(get_response).__call__


class AuthorizationMiddleware:
    """Django middleware to parse incoming access tokens, validate them and
    set an authorization function on the request.

    The decision to use a generic middleware rather than an
    AuthenticationMiddleware is explicitly made, because instances of the
    latter come with a number of assumptions (i.e. that user.is_authorized()
    exists, or that request.user uses the User model).

    Example usage:

    ::

        request.is_authorized_for()
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.middleware_settings = get_settings()

    @staticmethod
    def always_ok(*_args, **_kwargs):
        return True

    def authorize_function(self, scopes, token_signature, x_unique_id=None):
        """Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's scopes.

        :return func:
        """

        def is_authorized(*needed_scopes):
            granted_scopes = set(scopes)
            needed_scopes = set(needed_scopes)
            result = needed_scopes.issubset(granted_scopes)
            if needed_scopes and result:
                msg = "Granted access (needed: %s, granted: %s, token signature: %s)"
                args = [needed_scopes, granted_scopes, token_signature]
                if x_unique_id:
                    msg += " X-Unique-ID: %s"
                    args.append(x_unique_id)
                logger.info(msg, *args)
            return result

        return is_authorized

    @staticmethod
    def authorize_forced_anonymous(_):
        """Authorize function for routes that are forced anonymous"""
        raise RuntimeError("Should not call is_authorized_for in anonymous routes")

    def insufficient_scope_response(self):
        """Returns an HttpResponse object with a 401."""
        msg = 'Bearer realm="datapunt", error="insufficient_scope"'
        response = http.HttpResponse("Unauthorized", status=401)
        response["WWW-Authenticate"] = msg
        return response

    def expired_token_response(self):
        """Returns an HttpResponse object with a 401"""
        msg = 'Bearer realm="datapunt", error="expired_token"'
        response = http.HttpResponse("Unauthorized. Token expired.", status=401)
        response["WWW-Authenticate"] = msg
        return response

    def invalid_token_response(self):
        """Returns an HttpResponse object with a 401"""
        msg = 'Bearer realm="datapunt", error="invalid_token"'
        response = http.HttpResponse("Unauthorized", status=401)
        response["WWW-Authenticate"] = msg
        return response

    def invalid_request_response(self):
        """Returns an HttpResponse object with a 400"""
        msg = (
            'Bearer realm="datapunt", error="invalid_request", '
            'error_description="Invalid Authorization header format; '
            "should be: 'Bearer [token]'\""
        )
        response = http.HttpResponse("Bad Request", status=400)
        response["WWW-Authenticate"] = msg
        return response

    def parse_token(self, authz_header):
        """Get the token data present in the given authorization header."""
        prefix = authz_header[: len("Bearer ")]

        if prefix.lower() != "bearer ":
            logger.warning('Invalid authz header, does not start with "Bearer "')
            raise _AuthorizationHeaderError(self.invalid_request_response())

        raw_jwt = authz_header[len("Bearer ") :]
        try:
            jwt = self._decode_token(raw_jwt)
        except JWTMissingKey:
            check_update_keyset()
            try:
                jwt = self._decode_token(raw_jwt)
            except JWTMissingKey as e:
                logger.warning("API authz problem: unknown key. %s", e)
                raise _AuthorizationHeaderError(self.invalid_token_response()) from e

        claims = self.get_claims(jwt)
        sub = claims["sub"]
        scopes = claims["scopes"]
        claims = claims["claims"]
        token_signature = raw_jwt.split(".")[2]
        return scopes, token_signature, sub, claims

    def _decode_token(self, raw_jwt):
        settings = get_settings()
        keyset = get_keyset()  # does lazy loading here, inclusing fetching URLs

        check_claims = settings["CHECK_CLAIMS"] or None
        if check_claims:
            # Specifying check_claims disables the automatic check on expiry,
            # so that needs to be explicitly added now.
            check_claims = {**check_claims, "exp": int(time())}
        try:
            jwt = JWT(
                jwt=raw_jwt,
                key=keyset,
                algs=settings["ALLOWED_SIGNING_ALGORITHMS"],
                check_claims=check_claims,
            )
        except JWTExpired as e:
            logger.info("API authz problem: token expired %s", raw_jwt)
            raise _AuthorizationHeaderError(self.expired_token_response()) from e
        except JWTMissingKey:
            raise  # for parse_token() to handle
        except (JWException, ValueError) as e:
            # invalid signature, invalid claim, missing claim
            logger.warning("API authz problem: %s", e)
            raise _AuthorizationHeaderError(self.invalid_token_response()) from e
        return jwt

    def get_claims(self, jwt):
        claims = json.loads(jwt.claims)
        if "scopes" in claims:
            # Authz token structure
            return {
                "sub": claims.get("sub"),
                "scopes": claims["scopes"],
                "claims": claims,
            }
        elif claims.get("realm_access"):
            # Keycloak token structure
            return {
                "sub": claims.get("sub"),
                "scopes": {self.convert_scope(r) for r in claims["realm_access"]["roles"]},
                "claims": claims,
            }
        elif claims.get("roles") and (claims.get("unique_name") or claims.get("upn")):
            # Microsoft Entra ID token structure
            return {
                "sub": claims.get("unique_name", claims.get("upn")),
                "scopes": set(claims["roles"]),
                "claims": claims,
            }
        elif claims.get("groups") and (claims.get("unique_name") or claims.get("un")):
            # Microsoft Entra ID token structure (previously called Azure AD), using group claims
            return {
                "sub": claims.get("unique_name", claims.get("un")),
                "scopes": {
                    self.convert_scope(group.split(" ")[0]) for group in claims.get("groups")
                },
                "claims": claims,
            }
        else:
            logger.warning("API authz problem: access token misses scopes claim")
            raise _AuthorizationHeaderError(self.invalid_token_response())

    def convert_scope(self, scope):
        """Convert Keycloak role to authz style scope"""
        return scope.upper().replace("_", "/")

    def __call__(self, request):
        """Parses the Authorization header, decodes and validates the JWT and
        adds the is_authorized_for function to the request.
        """

        # Config is set to ALWAYS OK, authorisation check disabled
        if self.middleware_settings["ALWAYS_OK"]:
            logger.warning("API authz DISABLED")
            request.is_authorized_for = self.always_ok
            request.get_token_subject = "ALWAYS_OK"  # noqa: S105
            return self.get_response(request)

        # Path is in forced anonymous routes or method is Options
        forced_anonymous = any(
            request.path.startswith(route)
            for route in self.middleware_settings["FORCED_ANONYMOUS_ROUTES"]
        )

        if forced_anonymous or request.method == "OPTIONS":
            request.is_authorized_for = self.authorize_forced_anonymous
            request.get_token_subject = None
            return self.get_response(request)

        # Standard case
        scopes = []
        token_signature = ""
        subject = None
        claims = None

        x_unique_id = request.headers.get("x-unique-id")
        authz_header = request.headers.get("authorization")

        if authz_header:
            try:
                scopes, token_signature, subject, claims = self.parse_token(authz_header)
            except _AuthorizationHeaderError as e:
                return e.response

        authz_func = self.authorize_function(scopes, token_signature, x_unique_id)

        min_scope = self.middleware_settings["MIN_SCOPE"]
        if len(min_scope) > 0 and not authz_func(*min_scope):
            return self.insufficient_scope_response()

        PROTECTED = self.middleware_settings["PROTECTED"]
        for resource in PROTECTED:
            (route, protected_methods, required_scopes) = resource
            if (
                request.path.startswith(route)
                and _method_is_protected(request.method, protected_methods)
                and not authz_func(*required_scopes)
            ):
                return self.insufficient_scope_response()

        request.is_authorized_for = authz_func
        request.get_token_subject = subject
        request.get_token_scopes = scopes
        request.get_token_claims = claims
        return self.get_response(request)


def _method_is_protected(method, protected_methods):
    if method.upper() in protected_methods:
        return True
    return "*" in protected_methods and method.upper() != "OPTIONS"
