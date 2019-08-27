import base64
import collections
import json

import requests
from jwcrypto.jwk import JWKSet
from jwcrypto.common import JWException

from .config import get_settings, AuthzConfigurationError

_Key = collections.namedtuple('Key', 'alg key')
"""Immutable type for key storage"""

_keyset = None


class JWKError(Exception):
    """Error raised when parsing a JWKSet fails."""


def get_keyset():
    global _keyset
    if not _keyset:
        init_keyset()
    return _keyset


def init_keyset():
    global _keyset
    settings = get_settings()
    _keyset = JWKSet()

    if 'JWKS' in settings:
        try:
            _keyset.import_keyset(settings['JWKS'])
        except JWException as e:
            raise AuthzConfigurationError("Failed to load JWK from settings") from e

    if 'KEYCLOAK_JWKS_URL' in settings and settings['KEYCLOAK_JWKS_URL']:
        # Get and add public JWKS from Keycloak
        response = requests.get(settings['KEYCLOAK_JWKS_URL'])
        response.raise_for_status()

        try:
            _keyset.import_keyset(response.text)
        except JWException as e:
            raise AuthzConfigurationError("Failed to load JWK from url") from e

    if len(_keyset['keys']) == 0:
        raise AuthzConfigurationError('No verifier keys loaded!')

