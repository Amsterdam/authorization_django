"""
    authorization_middleware.config
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import types

from django.conf import settings as django_settings

# A sentinel object for required settings
_required = object()

# The Django settings key
_settings_key = 'DATAPUNT_AUTHZ'

# A list of all available settings, with default values
_available_settings = {
    'JWKS': _required,
    'KEYCLOAK_JWKS_URL': "",
    'MIN_SCOPE': tuple(),
    'ALWAYS_OK': False,
    'FORCED_ANONYMOUS_ROUTES': tuple(),
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

_settings = {}

# Validator functions and error messages
_settings_rectifiers = {
    'FORCED_ANONYMOUS_ROUTES': {
        'func': lambda s: s if type(s) in {list, tuple, set} else False,
        'errmsg': 'FORCED_ANONYMOUS_ROUTES must be a list, tuple or set'
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
            if new_value is False:
                raise AuthzConfigurationError(
                    'Error validating {}->{}: {}'.format(
                        _settings_key, key, rectifier['errmsg']))
            settings[key] = new_value
        except Exception as e:
            raise AuthzConfigurationError(
                'Error validating {}->{}: {}'.format(
                    _settings_key, key, rectifier['errmsg']
                )
            ) from e


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

    _rectify(user_settings)

    return types.MappingProxyType(user_settings)
