import base64
import collections
import json

import requests
from jwcrypto.jwk import JWKSet
from jwcrypto.common import JWException

from .config import get_settings, AuthzConfigurationError

_keyset = None


def get_keyset():
    global _keyset
    if not _keyset:
        init_keyset()
    return _keyset


def init_keyset():
    global _keyset
    settings = get_settings()
    _keyset = JWKSet()

    if settings.get('JWKS'):
        try:
            _keyset.import_keyset(settings['JWKS'])
        except JWException as e:
            raise AuthzConfigurationError("Failed to import keyset from settings") from e

    if settings.get('KEYCLOAK_JWKS_URL'):
        # Get public JWKS from Keycloak
        try:
            jwks_url = settings['KEYCLOAK_JWKS_URL']
            response = requests.get(jwks_url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise AuthzConfigurationError(
                "Failed to get Keycloak keyset from url: {}, error: {}".format(jwks_url, e)
            )
        try:
            _keyset.import_keyset(response.text)
        except JWException as e:
            raise AuthzConfigurationError("Failed to import Keycloak keyset") from e

    if len(_keyset['keys']) == 0:
        raise AuthzConfigurationError('No keys loaded!')
