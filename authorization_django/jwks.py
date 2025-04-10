from __future__ import annotations

import logging
import time

import requests
from jwcrypto.common import JWException
from jwcrypto.jwk import JWKSet

from .config import AuthzConfigurationError, get_settings

_keyset = None
_keyset_last_update = 0

logger = logging.getLogger(__name__)


def get_keyset() -> JWKSet:
    global _keyset
    if not _keyset:
        init_keyset()
    return _keyset


def check_update_keyset():
    """
    When loading a JWKS from a url (public endpoint), we might need to
    check sometimes if the JWKS has changed. To avoid too many requests to
    the url, we set a minimal interval between two checks.
    """
    settings = get_settings()
    current_time = time.time()
    if current_time - _keyset_last_update >= settings["MIN_INTERVAL_KEYSET_UPDATE"]:
        init_keyset()


def init_keyset():
    """
    Initialize keyset, by loading keyset from settings and/or from url
    """
    global _keyset, _keyset_last_update

    _keyset = JWKSet()
    _keyset_last_update = time.time()
    settings = get_settings()

    if settings.get("JWKS"):
        _load_jwks(_keyset, settings["JWKS"])

    if settings.get("JWKS_URL"):
        _load_jwks_from_url(_keyset, settings["JWKS_URL"])

    if settings.get("JWKS_URLS"):
        for url in settings["JWKS_URLS"]:
            _load_jwks_from_url(_keyset, url)

    if len(_keyset["keys"]) == 0:
        raise AuthzConfigurationError("No keys loaded!")


def _load_jwks(keyset: JWKSet, jwks):
    try:
        keyset.import_keyset(jwks)
    except JWException as e:
        raise AuthzConfigurationError("Failed to import keyset from settings") from e
    logger.info("Loaded JWKS from JWKS setting.")


def _load_jwks_from_url(keyset: JWKSet, jwks_url):
    try:
        response = requests.get(jwks_url, timeout=60)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise AuthzConfigurationError(
            f"Failed to get Keycloak keyset from url: {jwks_url}, error: {e}"
        ) from e
    try:
        keyset.import_keyset(response.text)
    except JWException as e:
        raise AuthzConfigurationError("Failed to import Keycloak keyset") from e
    logger.info("Loaded JWKS from JWKS_URL setting %s", jwks_url)
