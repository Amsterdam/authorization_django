"""
    datapunt.token
    ~~~~~~~~~~~~~~

    Authorization middleware for Django.
"""
import functools

from django.conf import settings
from django.core import exceptions
import jwt

import authorization_levels as levels
"""
`levels` is part of the public interface of this module.
"""

def authorization_middleware(get_response):
    """ Django middleware to parse incoming access tokens, validate them and
    set an authorization function on the request.

    :todo: don't allow requests without a token

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
        Nested function 'middleware' allows both 'JWT' (not IANA-registered) and
        'Bearer' as Authorization header prefix; f we stop using Django's JWT
        plugin, this should be cleaned.
    """
    key = settings.JWT_SECRET_KEY
    algorithm = settings.JWT_ALGORITHM
    invalid_format_msg = ('Invalid Authorization header format;'
                          'should be "JWT [token]"')

    def authorize_function(level):
        """ Creates a partial around :func:`levels.is_authorized`
        that wraps the current user's authorization `level` (the `granted`
        parameter).

        :return func:
        """
        return functools.partial(levels.is_authorized, level)

    def middleware(request):
        """ TODO: Documentation
        """
        authorization = request.META.get('HTTP_AUTHORIZATION', '')

        if authorization:

            try:
                prefix, token = authorization.split()
            except ValueError:
                raise exceptions.SuspiciousOperation(invalid_format_msg)
            if prefix not in ('JWT', 'Bearer',):
                raise exceptions.SuspiciousOperation(invalid_format_msg)

            try:
                decoded = jwt.decode(token, key=key, algorithms=(algorithm,))
            except jwt.InvalidTokenError as e:
                raise exceptions.SuspiciousOperation() from e

            request.is_authorized_for = authorize_function(decoded['authz'])

        else:
            request.is_authorized_for = authorize_function(
                levels.LEVEL_DEFAULT
            )

        response = get_response(request)

        return response

    return middleware
