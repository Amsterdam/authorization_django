"""
    authorization_django.middleware
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import functools
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

    def authorize_function(level):
        """ Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's authorization `level` (the `granted`
        parameter).

        :return func:
        """
        return functools.partial(levels.is_authorized, level)

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
            "error_description=\"Invalid Authorization header format; should be"
            "'Bearer [token]'\"")
        response = http.HttpResponse('Bad Request', status=400)
        response['WWW-Authenticate'] = msg
        return response

    def middleware(request):
        """ Parses the Authorization header, decodes and validates the JWT and
        adds the is_authorized_for function to the request.
        """
        authorization = request.META.get('HTTP_AUTHORIZATION')

        if authorization:

            try:
                prefix, token = authorization.split()
            except ValueError:
                logger.warning(
                    'Invalid Authorization header: {}'.format(authorization))
                return invalid_request()
            # todo: do not allow JWT prefix
            if prefix not in ('JWT', 'Bearer',):
                logger.warning(
                    'Invalid Authorization header: {}'.format(authorization))
                return invalid_request()

            try:
                decoded = jwt.decode(token, key=key, algorithms=(algorithm,))
            except jwt.InvalidTokenError:
                logger.warning('Invalid JWT token: {}'.format(token))
                return invalid_token()

            # todo: fail if authz is not present
            authz = decoded.get('authz', levels.LEVEL_DEFAULT)

        else:
            authz = levels.LEVEL_DEFAULT

        request.is_authorized_for = authorize_function(authz)

        response = get_response(request)

        return response

    return middleware
