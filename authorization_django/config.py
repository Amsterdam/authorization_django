"""
    authorization_middleware.config
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import functools
import logging
import types

from django.conf import settings as django_settings
import authorization_levels

# A sentinel object for required settings
_required = object()

# The Django settings key
_settings_key = 'DATAPUNT_AUTHZ'

# A list of all available settings, with default values
_available_settings = {
    'JWT_SECRET_KEY': _required,
    'JWT_ALGORITHM': _required,
    'MIN_SCOPE': authorization_levels.LEVEL_DEFAULT,
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

# Validator functions and error messages
_settings_rectifiers = {
    'JWT_SECRET_KEY': {
        'func': lambda s: len(bytes(s, 'utf-8')) >= 16 and bytes(s, 'utf-8'),
        'errmsg': 'jwt key must be a str with at least 16 ascii characters'
    },
    'JWT_ALGORITHM': {
        'func': lambda s: s == 'HS256' and s,
        'errmsg': 'jwt algorithm must be HS256'
    }
}

# Preprocessing: the set of all available configuration keys
_available_settings_keys = set(_available_settings.keys())

# Preprocessing: the set of all required configuration keys
_required_settings_keys = {
    key for key, setting in _available_settings.items() if setting is _required
}


class AuthzConfigurationError(Exception):
    """ Error for missing / invalid configuration"""


def _rectify(settings):
    """ Rectify (and validate) the given settings using the functions in
    :data:`_settings_rectifiers`.
    """
    for key, rectifier in _settings_rectifiers.items():
        try:
            new_value = rectifier['func'](settings[key])
            if not new_value:
                raise AuthzConfigurationError(
                    'Error validating {}->{}: {}'.format(
                        _settings_key, key, rectifier['errmsg']))
            settings[key] = new_value
        except:
            raise AuthzConfigurationError(
                'Error validating {}->{}: {}'.format(
                    _settings_key, key, rectifier['errmsg']))


@functools.lru_cache(maxsize=1)
def settings():
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

    _rectify(user_settings)
    return types.MappingProxyType(user_settings)
