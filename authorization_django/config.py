"""
    authorization_middleware.config
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import types

from django.conf import settings as django_settings

# A sentinel object for required settings
_required = object()

# The Django settings key
_settings_key = 'DATAPUNT_AUTHZ'

# A list of all available settings, with default values
_available_settings = {
    'JWKS': "",
    'JWKS_URL': "",
    'ALLOWED_SIGNING_ALGORITHMS': [
        'ES256', 'ES384', 'ES512',
        'RS256', 'RS384', 'RS512'
    ],
    'MIN_SCOPE': tuple(),
    'PROTECTED': [],
    'ALWAYS_OK': False,
    'FORCED_ANONYMOUS_ROUTES': tuple(),
    'MIN_INTERVAL_KEYSET_UPDATE': 30
}

_methods_valid_options = [
    '*', 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE'
]

_settings = {}

# Preprocessing: the set of all available configuration keys
_available_settings_keys = set(_available_settings.keys())

# Preprocessing: the set of all required configuration keys
_required_settings_keys = {
    key for key, setting in _available_settings.items() if setting is _required
}


class AuthzConfigurationError(Exception):
    """ Error for missing / invalid configuration """

class ProtectedRouteConflictError(AuthzConfigurationError):
    """ Error for a conflicting protected route configuration """

class ProtectedRecourceSyntaxError(AuthzConfigurationError):
    """ Syntax error in configuration of protected resource """

class NoRequiredScopesError(AuthzConfigurationError):
    """ Error for when route is configured as protected
    but no required scopes have been set
    """

def init_settings():
    global _settings
    _settings = load_settings()


def get_settings():
    global _settings
    if not _settings:
        init_settings()
    return _settings


def load_settings():
    """ Fetch the middleware settings.

    :return dict: settings
    """
    # Get the user-provided settings
    user_settings = dict(getattr(django_settings, _settings_key, {}))
    user_settings_keys = set(user_settings.keys())

    # Check for required but missing settings
    missing = _required_settings_keys - user_settings_keys
    if missing:
        raise AuthzConfigurationError(
            'Missing required {} config: {}'.format(_settings_key, missing))

    # Check for unknown settings
    unknown = user_settings_keys - _available_settings_keys
    if unknown:
        raise AuthzConfigurationError(
            'Unknown {} config params: {}'.format(_settings_key, unknown))

    # Merge defaults with provided settings
    defaults = _available_settings_keys - user_settings_keys
    user_settings.update({key: _available_settings[key] for key in defaults})

    if not user_settings.get('JWKS') and not user_settings.get('JWKS_URL'):
        raise AuthzConfigurationError(
            'Either JWKS or JWKS_URL must be set, or both'
        )

    if type(user_settings['MIN_SCOPE']) == str:
        user_settings['MIN_SCOPE'] = (user_settings['MIN_SCOPE'], )

    if not type(user_settings['FORCED_ANONYMOUS_ROUTES']) in {list, tuple, set}:
        raise AuthzConfigurationError(
            'FORCED_ANONYMOUS_ROUTES must be a list, tuple or set'
        )

    if not type(user_settings['PROTECTED']) in {list, tuple, set}:
        raise AuthzConfigurationError(
            'PROTECTED must be a list, tuple or set'
        )

    for resource in user_settings['PROTECTED']:
        if not type(resource) == tuple or not len(resource) == 3:
            raise ProtectedRecourceSyntaxError(
                'Resource in PROTECTED must be a tuple of length 3'
            )
        (route, methods, scopes) = resource
        if not type(route) is str:
            raise AuthzConfigurationError(
                'Route in PROTECTED resource must be a string'
            )
        for aroute in user_settings['FORCED_ANONYMOUS_ROUTES']:
            if route.startswith(aroute):
                raise ProtectedRouteConflictError(
                    f'{route} is configured in PROTECTED, but this would be '
                    f'overruled by {aroute} in FORCED_ANONYMOUS_ROUTES'
                )
        if not type(methods) is list:
            raise AuthzConfigurationError(
                'Methods in PROTECTED resource must be a list'
            )
        for method in methods:
            if not method in _methods_valid_options:
                str_methods = ', '.join(_methods_valid_options)
                raise AuthzConfigurationError(
                    f'Invalid value for methods: {method}. Must be one of {str_methods}.'
                )
        if not type(scopes) is list:
            raise AuthzConfigurationError(
                'Scopes in PROTECTED resource must be a list'
            )
        if not len(scopes) > 0:
            raise NoRequiredScopesError(
                f'You must require at least one scope for protected route {route}'
            )

    return types.MappingProxyType(user_settings)
