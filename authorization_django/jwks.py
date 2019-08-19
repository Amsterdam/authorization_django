import base64
import collections
import json
from types import MappingProxyType

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.utils import int_from_bytes

from .config import get_settings, AuthzConfigurationError

_Key = collections.namedtuple('Key', 'alg key')
"""Immutable type for key storage"""

_keyset = None


class JWKError(Exception):
    """Error raised when parsing a JWKSet fails."""


def get_keyset():
    global _keyset
    if not _keyset:
        _keyset = init_keyset()
    return _keyset


def init_keyset():
    settings = get_settings()
    keyset = {
        'signers': {},
        'verifiers': {}
    }
    if 'JWKS' in settings:
        try:
            jwks_json = json.loads(settings['JWKS'])
        except json.JSONDecodeError:
            raise AuthzConfigurationError('Provided JWKS is invalid JSON')

        try:
            ks = load(jwks_json)
            keyset['signers'].update(ks['signers'])
            keyset['verifiers'].update(ks['verifiers'])
        except JWKError:
            raise AuthzConfigurationError(
                'Must provide a valid JWKSet. See RFC 7517 and 7518 for details.')

    if 'KEYCLOAK_JWKS_URL' in settings and settings['KEYCLOAK_JWKS_URL']:
        # Get and add public JWKS from Keycloak
        response = requests.get(settings['KEYCLOAK_JWKS_URL'])
        response.raise_for_status()
        try:
            keycloak_jwks = response.json()
        except ValueError:
            raise(AuthzConfigurationError('Got invalid JSON from Keycloak'))
        try:
            ks = load(keycloak_jwks)
            keyset['signers'].update(ks['signers'])
            keyset['verifiers'].update(ks['verifiers'])
        except JWKError:
            raise AuthzConfigurationError('Failed to load Keycloak JWKS')

    if len(keyset['verifiers']) == 0:
        raise AuthzConfigurationError('No verifier keys loaded!')
    return keyset


def load(jwks):
    """Parse a JWKSet and return a dictionary that maps key IDs on keys."""
    signers = {}
    verifiers = {}

    try:
        for key in jwks['keys']:
            for op in key.get('key_ops', ['verify']):
                if op == 'sign':
                    keys = signers
                else:
                    keys = verifiers

                if key['kty'] == 'oct':
                    _key = _Key(alg=key['alg'], key=base64.urlsafe_b64decode(key['k']))
                elif key['kty'] == 'RSA':
                    _key = _Key(alg=key['alg'], key=base64.urlsafe_b64decode(key['x5c']))
                elif key['kty'] == 'EC':
                    alg, ec_key = _load_ecdsa(key, op)
                    _key = _Key(alg=alg, key=ec_key)
                else:
                    raise JWKError("Unsupported key type: {}".format(key['kty']))

                keys[key['kid']] = _key
    except KeyError as e:
        raise JWKError() from e

    return {
        'signers': signers,
        'verifiers': verifiers
    }


def _load_ecdsa(key, key_op):
    if key.get('kty') != 'EC':
        raise JWKError('Not an Elliptic curve key')

    if 'x' not in key or 'y' not in key:
        raise JWKError('Not an Elliptic curve key')

    x = base64.urlsafe_b64decode(key.get('x'))
    y = base64.urlsafe_b64decode(key.get('y'))

    curve = key.get('crv')
    if curve == 'P-256':
        if len(x) == len(y) == 32:
            alg = 'ES256'
            curve_obj = ec.SECP256R1()
        else:
            raise JWKError("Coords should be 32 bytes for curve P-256")
    elif curve == 'P-384':
        if len(x) == len(y) == 48:
            alg = "ES384"
            curve_obj = ec.SECP384R1()
        else:
            raise JWKError("Coords should be 48 bytes for curve P-384")
    elif curve == 'P-521':
        if len(x) == len(y) == 66:
            alg = "ES512"
            curve_obj = ec.SECP521R1()
        else:
            raise JWKError("Coords should be 66 bytes for curve P-521")
    else:
        raise JWKError("Invalid curve: {}".format(curve))

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int_from_bytes(x, 'big'), y=int_from_bytes(y, 'big'), curve=curve_obj
    )

    if key_op == 'sign':
        if 'd' not in key:
            raise JWKError("Signing ECDSA keys must contain private key")

        d = base64.urlsafe_b64decode(key.get('d'))
        if len(d) != len(x):
            raise JWKError("D should be {} bytes for curve {}", len(x), curve)

        key = ec.EllipticCurvePrivateNumbers(
            int_from_bytes(d, 'big'),
            public_numbers
        ).private_key(default_backend())
    else:
        key = public_numbers.public_key(default_backend())

    return alg, key
