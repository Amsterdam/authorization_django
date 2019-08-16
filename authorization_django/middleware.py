"""
    authorization_django.middleware
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import sys

import jwt

from django import http
from django.conf import settings as django_settings

from .config import get_settings
from .jwks import get_keyset


def _create_logger(middleware_settings):
    """ Creates a logger using the given settings.
    """
    if django_settings.DEBUG:
        level = logging.DEBUG
        formatter = logging.Formatter(
            middleware_settings['LOGGER_FORMAT_DEBUG'])
    else:
        level = middleware_settings['LOGGER_LEVEL']
        formatter = logging.Formatter(middleware_settings['LOGGER_FORMAT'])

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(formatter)

    logger = logging.getLogger(middleware_settings['LOGGER_NAME'])

    # If in some strange way this logger already exists we make sure to delete
    # its existing handlers
    del logger.handlers[:]

    logger.addHandler(handler)

    # Disable propagation by default
    logger.propagate = False

    return logger


class _AuthorizationHeaderError(Exception):

    def __init__(self, response):
        self.response = response


def authorization_middleware(get_response):
    """ Django middleware to parse incoming access tokens, validate them and
    set an authorization function on the request.

    The decision to use a generic middleware rather than an
    AuthenticationMiddleware is explicitly made, because inctances of the
    latter come with a number of assumptions (i.e. that user.is_authorized()
    exists, or that request.user uses the User model).

    Example usage:

    ::

        request.is_authorized_for()

    :param get_response: callable that creates the response object
    :return: response
    """
    middleware_settings = get_settings()
    logger = _create_logger(middleware_settings)

    def get_token_subject(sub):
        return sub

    def always_ok(*args, **kwargs):
        return True

    def authorize_function(scopes, token_signature, x_unique_id=None):
        """ Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's scopes.

        :return func:
        """
        log_msg_scopes = 'Granted access (needed: {}, granted: {}, token: {})'

        def is_authorized(*needed_scopes):
            granted_scopes = set(scopes)
            needed_scopes = set(needed_scopes)
            result = needed_scopes.issubset(granted_scopes)
            if result:
                msg = log_msg_scopes.format(needed_scopes, granted_scopes, token_signature)
                if x_unique_id:
                    msg += ' X-Unique-ID: {}'.format(x_unique_id)
                logger.info(msg)
            return result

        return is_authorized

    def authorize_forced_anonymous(_):
        """ Authorize function for routes that are forced anonymous"""
        raise Exception('Should not call is_authorized_for in anonymous routes')

    def insufficient_scope():
        """Returns an HttpResponse object with a 401."""
        msg = 'Bearer realm="datapunt", error="insufficient_scope"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def expired_token():
        """ Returns an HttpResponse object with a 401
        """
        msg = 'Bearer realm="datapunt", error="expired_token"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def invalid_token():
        """ Returns an HttpResponse object with a 401
        """
        msg = 'Bearer realm="datapunt", error="invalid_token"'
        response = http.HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = msg
        return response

    def invalid_request():
        """ Returns an HttpResponse object with a 400
        """
        msg = (
            "Bearer realm=\"datapunt\", error=\"invalid_request\", "
            "error_description=\"Invalid Authorization header format; "
            "should be: 'Bearer [token]'\"")
        response = http.HttpResponse('Bad Request', status=400)
        response['WWW-Authenticate'] = msg
        return response

    def token_data(authz_header):
        """ Get the token data present in the given authorization header.
        """
        try:
            prefix, token = authz_header.split()
        except ValueError:
            logger.warning('Invalid authz header: {}'.format(authz_header))
            raise _AuthorizationHeaderError(invalid_request())

        if prefix.lower() != 'bearer':
            logger.warning('Invalid authz header: {}'.format(authz_header))
            raise _AuthorizationHeaderError(invalid_request())

        decoded = decode_token(token)

        if 'scopes' not in decoded:
            logger.warning('Access token misses scopes claim: {}'.format(token))
            raise _AuthorizationHeaderError(invalid_token())
        else:
            scopes = decoded['scopes']

        sub = decoded.get('sub')
        token_signature = token.split('.')[2]
        return scopes, token_signature, sub

    def get_verification_key(header):
        if 'kid' not in header:
            logger.exception("Key identifier field missing in header")
            raise _AuthorizationHeaderError(invalid_token())

        kid = header['kid']
        keyset = get_keyset()
        if kid not in keyset['verifiers']:
            logger.exception("Unknown key identifier: {}".format(header['kid']))
            raise _AuthorizationHeaderError(invalid_token())
        return keyset['verifiers'][kid]

    def decode_token(token):
        try:
            header = jwt.get_unverified_header(token)
        except jwt.ExpiredSignatureError:
            logger.info("Expired token")
            raise _AuthorizationHeaderError(expired_token())
        except (jwt.InvalidTokenError, jwt.DecodeError):
            logger.exception("JWT decode error while reading header")
            raise _AuthorizationHeaderError(invalid_token())

        key = get_verification_key(header)
        try:
            decoded = jwt.decode(token, key=key.key, algorithms=(key.alg,))
        except jwt.InvalidTokenError:
            logger.exception('Could not decode access token {}'.format(token))
            raise _AuthorizationHeaderError(invalid_token())
        return decoded

    def middleware(request):
        """ Parses the Authorization header, decodes and validates the JWT and
        adds the is_authorized_for function to the request.
        """

        # Config is set to ALWAYS OK, authorisation check disabled
        if middleware_settings['ALWAYS_OK']:
            logger.warning('API authz DISABLED')
            request.is_authorized_for = always_ok
            request.get_token_subject = 'ALWAYS_OK'
            return get_response(request)

        # Path is in forced anonymous routes or method is Options
        forced_anonymous = any(
            request.path.startswith(route)
            for route in middleware_settings['FORCED_ANONYMOUS_ROUTES'])

        if forced_anonymous or request.method == 'OPTIONS':
            request.is_authorized_for = authorize_forced_anonymous
            request.get_token_subject = None
            return get_response(request)

        # Standard case
        scopes = []
        token_signature = ''
        subject = None

        x_unique_id = request.META.get('HTTP_X_UNIQUE_ID')
        authz_header = request.META.get('HTTP_AUTHORIZATION')

        if authz_header:
            try:
                scopes, token_signature, subject = token_data(authz_header)
            except _AuthorizationHeaderError as e:
                return e.response

        authz_func = authorize_function(scopes, token_signature, x_unique_id)

        min_scope = middleware_settings['MIN_SCOPE']
        if len(min_scope) > 0 and not authz_func(min_scope):
            return insufficient_scope()

        request.is_authorized_for = authz_func
        request.get_token_subject = subject
        return get_response(request)

    return middleware
