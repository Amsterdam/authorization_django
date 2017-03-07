"""
    authorization_django
    ~~~~~~~~~~~~~~~~~~~~

    Authorization middleware that uses JWTs for authentication.

    The following settings are used by the middleware, and can be configured in
    your ``settings.py`` in the ``DATAPUNT_AUTHZ`` dictionary.

    .. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

    ================================= =========================================
    ``JWT_SECRET_KEY``                (Required) Your JWT signing key
    ``JWT_ALGORITHM``                 (Required) Algorithm to use for the JWT
                                      message authentication code (MAC)
    ``LOGGER_NAME``                   Name of the logger. (Default =
                                      ``authorization_django``)
    ``LOGGER_LEVEL``                  Log level. Will be overwritten if running
                                      debug mode. (Default = ``INFO``)
    ``LOGGER_FORMAT``                 Log format
    ``LOGGER_FORMAT_DEBUG``           Log format for messages in debug mode

"""
import functools
import logging
import sys

from django.conf import settings
from django import http
import jwt

import authorization_levels as levels
"""
`levels` is part of the public interface of this module.
"""

_required_setting_sentinel = object()
_settings_key = 'DATAPUNT_AUTHZ'
_available_settings = {
    'JWT_SECRET_KEY': _required_setting_sentinel,
    'JWT_ALGORITHM': _required_setting_sentinel,
    'LOGGER_NAME': __name__,
    'LOGGER_LEVEL': logging.INFO,
    'LOGGER_FORMAT': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    'LOGGER_FORMAT_DEBUG': (
        '-' * 80 + '\n' +
        '%(levelname)s in %(module)s [%(pathname)s:%(lineno)d]:\n' +
        '%(message)s\n' +
        '-' * 80
    )
}
_available_settings_keys = set(_available_settings.keys())
_required_settings_keys = {
    key for key in _available_settings if _available_settings[key] is _required_setting_sentinel
}


class AuthzConfigurationError(Exception):
    """ Error for missing / wrong configuration
    """


def _middleware_settings():
    """ Fetch the middleware settings.

    :return dict: settings
    """
    # Get the user-provided settings
    user_settings = dict(getattr(settings, _settings_key, {}))
    user_settings_keys = set(user_settings.keys())
    # Check for required but missing settings
    missing = _required_settings_keys - user_settings_keys
    if missing:
        raise AuthzConfigurationError('Missing required config params in {}: {}'.format(_settings_key, missing))
    # Check for unknown settings
    unknown = user_settings_keys - _available_settings_keys
    if unknown:
        raise AuthzConfigurationError('Unknown config params in {}: {}'.format(_settings_key, unknown))
    # Merge defaults with provided settings
    defaults = _available_settings_keys - user_settings_keys
    user_settings.update({key: _available_settings[key] for key in defaults})

    return user_settings


def _create_logger(middleware_settings):
    """ Creates a logger using the given settings.
    """
    level = (settings.DEBUG and logging.DEBUG) or middleware_settings['LOGGER_LEVEL']
    formatter = logging.Formatter((settings.DEBUG and middleware_settings['LOGGER_FORMAT_DEBUG']) or middleware_settings['LOGGER_FORMAT'])

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(formatter)

    logger = logging.getLogger(middleware_settings['LOGGER_NAME'])

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
    middleware_settings = _middleware_settings()
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
        msg = "Bearer realm=\"datapunt\", error=\"invalid_request\", error_description=\"Invalid Authorization header format; should be 'Bearer [token]'\""
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
                logger.warning('Invalid Authorization header: {}'.format(authorization))
                return invalid_request()
            # todo: do not allow JWT prefix
            if prefix not in ('JWT', 'Bearer',):
                logger.warning('Invalid Authorization header: {}'.format(authorization))
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
