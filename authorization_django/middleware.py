"""
    authorization_django.middleware
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import sys

import authorization_levels as levels
from django import http
from django.conf import settings as django_settings
import jwt

from .config import settings


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

        request.is_authorized_for(levels.LEVEL_EMPLOYEE)

    :param get_response: callable that creates the response object
    :return: response
    :todo:
        Two things needs to be done when we can completely remove the Django
        JWT plugin:

        - Nested function 'middleware' allows both 'JWT' (not IANA-registered)
          and 'Bearer' as Authorization header prefix; JWT should not be
          accepted.
        - The Django JWT middleware does not include the authz claim, so this
          plugin does not fail if it is not present; this behavior is wrong
          when we no longer use the Django JWT plugin.
    """
    middleware_settings = settings()
    logger = _create_logger(middleware_settings)

    key = middleware_settings['JWT_SECRET_KEY']
    algorithm = middleware_settings['JWT_ALGORITHM']
    min_scope = middleware_settings['MIN_SCOPE']

    def authorize_function(level, token_signature):
        """ Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's authorization `level` (the `granted`
        parameter).

        :return func:
        """
        log_msg = 'Granted access (assigned: {}, needed: {}, token: {})'

        def is_authorized(needed):
            result = levels.is_authorized(level, needed)
            if result:
                msg = log_msg.format(bin(level), bin(needed), token_signature)
                logger.info(msg)
            return result

        return is_authorized

    def authorize_forced_anonymous(_):
        """ Authorize function for routes that are forced anonymous"""
        raise Exception(
            'Should not call is_authorized_for in anonymous routes')

    def insufficient_scope():
        """Returns an HttpResponse object with a 401."""
        msg = 'Bearer realm="datapunt", error="insufficient_scope"'
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

    def token_data(authorization):
        """ Get the token data present in the given authorization header.
        """
        try:
            prefix, token = authorization.split()
        except ValueError:
            logger.warning(
                'Invalid Authorization header: {}'.format(authorization))
            raise _AuthorizationHeaderError(invalid_request())
        if prefix != 'Bearer':
            logger.warning(
                'Invalid Authorization header: {}'.format(authorization))
            raise _AuthorizationHeaderError(invalid_request())

        try:
            decoded = jwt.decode(token, key=key, algorithms=(algorithm,))
        except jwt.InvalidTokenError:
            logger.warning('API authz problem: could not decode access '
                           'token {}'.format(token))
            raise _AuthorizationHeaderError(invalid_token())

        try:
            authz = decoded['authz']
        except KeyError:
            logger.warning('API authz problem: access token misses '
                           'authz claim: {}'.format(token))
            raise _AuthorizationHeaderError(invalid_token())

        token_signature = token.split('.')[2]
        return authz, token_signature

    def middleware(request):
        """ Parses the Authorization header, decodes and validates the JWT and
        adds the is_authorized_for function to the request.
        """
        # requests that are in FORCED_ANONYMOUS_ROUTES are accepted
        request_path = request.path
        forced_anonymous = any(
            request_path.startswith(route)
            for route in middleware_settings['FORCED_ANONYMOUS_ROUTES'])
        is_options = request.method == 'OPTIONS'
        if forced_anonymous or is_options:
            authz_func = authorize_forced_anonymous
        else:
            authorization = request.META.get('HTTP_AUTHORIZATION')
            token_signature = ''

            if authorization:
                try:
                    authz, token_signature = token_data(authorization)
                except _AuthorizationHeaderError as e:
                    return e.response
            else:
                authz = levels.LEVEL_DEFAULT

            authz_func = authorize_function(authz, token_signature)

            if not authz_func(min_scope):
                return insufficient_scope()

        request.is_authorized_for = authz_func

        response = get_response(request)

        return response

    return middleware
