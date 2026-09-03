from __future__ import annotations

import json
import logging
import time
from collections import defaultdict

import requests
from jwcrypto.common import JWException
from jwcrypto.jwk import JWKSet

from .config import AuthzConfigurationError, get_settings

logger = logging.getLogger(__name__)


class JWKSWrapper:
    """
    Wrapper for JWKSet to provide a method to check and update the keyset if needed.
    """

    def __init__(self):
        self._settings = get_settings()
        self.init_keyset()

    def init_keyset(self):
        """
        Initialize keyset, by loading keyset from settings and/or from url
        """
        self._keyset: dict[str, JWKSet] = defaultdict(JWKSet)
        self._keyset_last_update = time.time()

        for trusted_jwks_item in self._settings.TRUSTED_JWKS:
            if url := trusted_jwks_item.jwks_url:
                _load_jwks_from_url(self._keyset[url], url)
            elif jwks := trusted_jwks_item.jwks:
                _load_jwks(self._keyset["JWKS"], jwks)

        if not any(len(keyset["keys"]) > 0 for keyset in self._keyset.values()):
            raise AuthzConfigurationError("No keys loaded!")

    @property
    def keyset(self):
        return self._keyset

    def get_key(self, kid):
        for keyset in self._keyset.values():
            for key in keyset["keys"]:
                if key.get("kid") == kid:
                    return key
        return None

    def check_update_keyset(self):
        """
        When loading a JWKS from a url (public endpoint), we might need to
        check sometimes if the JWKS has changed. To avoid too many requests to
        the url, we set a minimal interval between two checks.
        """
        current_time = time.time()
        if current_time - self._keyset_last_update >= self._settings.MIN_INTERVAL_KEYSET_UPDATE:
            self.init_keyset()


def _load_jwks(keyset: JWKSet, jwks):
    try:
        keyset.import_keyset(json.dumps(jwks))
    except JWException as e:
        raise AuthzConfigurationError("Failed to import keyset from settings") from e
    logger.info("Loaded JWKS from JWKS setting.")


def _load_jwks_from_url(keyset: JWKSet, jwks_url):
    try:
        response = requests.get(jwks_url, timeout=60)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise AuthzConfigurationError(
            f"Failed to get keyset from url: {jwks_url}, error: {e}"
        ) from e
    try:
        keyset.import_keyset(response.text)
    except JWException as e:
        raise AuthzConfigurationError("Failed to import keyset") from e
    logger.info("Loaded JWKS from JWKS_URL setting %s", jwks_url)
