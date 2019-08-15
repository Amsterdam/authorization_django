"""
    authorization_middleware.config
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import functools
import logging
import types
import requests
import json
from json import JSONDecodeError

from . import jwks
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

# Validator functions and error messages
_settings_rectifiers = {
    'FORCED_ANONYMOUS_ROUTES': {
        'func': lambda s: type(s) in {list, tuple, set} and s,
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

    user_settings['JWKS'] = load_jwks(user_settings)
    return types.MappingProxyType(user_settings)


def load_jwks(user_settings):
    keyset = {}
    if 'JWKS' in user_settings:
        try:
            keyset = json.loads(user_settings['JWKS'])
        except JSONDecodeError:
            raise AuthzConfigurationError('Provided JWKS is invalid JSON')

        try:
            ks = jwks.load(user_settings['JWKS'])
            keyset['signers'].update(ks['signers'])
            keyset['verifiers'].update(ks['verifiers'])
        except jwks.JWKError:
            raise AuthzConfigurationError(
                'Must provide a valid JWKSet. See RFC 7517 and 7518 for details.')

    if 'KEYCLOAK_JWKS_URL' in settings:
        # Get and add public JWKS from Keycloak
        # construct url (need base url, realm..)
        if settings.KEYCLOAK_JWKS_URL:
            response = requests.get(settings.KEYCLOAK_JWKS_URL)
            response.raise_for_status()
            try:
                keycloak_jwks = response.json()
            except ValueError:
                raise(AuthzConfigurationError('Got invalid JSON from Keycloak'))
            try:
                ks = jwks.load(keycloak_jwks)
                keyset['signers'].update(ks['signers'])
                keyset['verifiers'].update(ks['verifiers'])
            except jwks.JWKError:
                raise AuthzConfigurationError('Failed to load Keycloak JWKS')

    return keyset

