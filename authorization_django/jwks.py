import base64
import collections
import json
from types import MappingProxyType

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key


# ASN.1 Identifier Octet settings
_ASN1_TAG_SEQUENCE = 0b10000
_ASN1_TAG_OBJECT_IDENTIFIER = 0b110
_ASN1_TAG_INTEGER = 0b10
_ASN1_TAG_BITSTRING = 0b11
_ASN1_TAG_OCTETSTRING = 0b100
_ASN1_CONTEXT_SPECIFIC = 0b10000000
_ASN1_CONSTRUCTED = 0b100000

# ASN.1 Object Identifiers for EC public key and curves
_ASN1_OID_PUBKEY = b'\x2a\x86\x48\xce\x3d\x02\x01'  # 1.2.840.10045.2.1
_ASN1_OID_CURVE_P256 = b'\x2a\x86\x48\xce\x3d\x03\x01\x07'  # 1.2.840.10045.3.1.7
_ASN1_OID_CURVE_P384 = b'\x2b\x81\x04\x00\x22'  # 1.3.132.0.34
_ASN1_OID_CURVE_P521 = b'\x2b\x81\x04\x00\x23'  # 1.3.132.0.35


_Key = collections.namedtuple('Key', 'alg key')
"""Immutable type for key storage"""

_KeySet = collections.namedtuple('KeySet', 'signers verifiers')
"""Immutable type for key sets"""


class JWKError(Exception): pass
"""Error raised when parsing a JWKSet fails."""


def load(jwks):
    """Parse a JWKSet and return a dictionary that maps key IDs on keys."""
    sign_keys = {}
    verify_keys = {}
    try:
        keyset = json.loads(jwks)
        for key in keyset['keys']:
            for op in key['key_ops']:
                if op == 'sign':
                    k = sign_keys
                elif op == 'verify':
                    k = verify_keys
                else:
                    raise JWKError("Unsupported key operation: {}".format(op))
                if key['kty'] == 'oct':
                    k[key['kid']] = _Key(alg=key['alg'], key=key['k'])
                elif key['kty'] == 'EC':
                    if key['crv'] == 'P-256':
                        alg = 'ES256'
                    elif key['crv'] == 'P-384':
                        alg = 'ES384'
                    elif key['crv'] == 'P-521':
                        alg = 'ES512'
                    if op == 'sign':  # ECDSA private
                        derkey = load_der_private_key(
                            _encode_private_ecdsa_key(key['d'], key['x'], key['y']), None, default_backend()
                        )
                    else:
                        derkey = load_der_public_key(_encode_public_ecdsa_key(key['x'], key['y']), default_backend())
                    k[key['kid']] = _Key(alg=alg, key=derkey)
                else:
                    raise JWKError("Unsupported key type: {}".format(key['kty']))
    except (KeyError, json.JSONDecodeError) as e:
        raise JWKError() from e
    keys = _KeySet(signers=MappingProxyType(sign_keys), verifiers=MappingProxyType(verify_keys))
    return keys


def _object_id_curve(p):
    """Determine object identifier of the curve for the given point."""
    if 32 == len(p):  # secp256r1 / p-256
        return _ASN1_OID_CURVE_P256
    elif 48 == len(p):  # secp384r1 / p-384
        return _ASN1_OID_CURVE_P384
    elif 66 == len(p):  # secp521r1 / p-521
        return _ASN1_OID_CURVE_P521
    return None


def _encode_length(length):
    """Object length is encoded as a single octet for lengths <= 127 octets and in max 1 + 127 octets for everything >
    127 octets."""
    res = bytearray()
    if length <= 127:
        res.append(length)
    else:
        lengthbytes = bytearray()
        while length > 0:
            lengthbytes.append(length & 0xFF)
            length = length >> 8
        if len(lengthbytes) > 127:
            raise Exception("Cannot encode objects this long in ASN.1")
        res.append(0b10000000 | len(lengthbytes))
        res.extend(lengthbytes)
    return bytes(res)


def _encode_ec_point(x, y):
    """A point on the curve is encoded as an ASN.1 bit string."""
    ec_point = bytearray()
    ec_point.append(_ASN1_TAG_BITSTRING)
    ec_point.extend(_encode_length(2 + len(x)*2))
    ec_point.append(0)  # no unused bits
    ec_point.append(4)  # no compression
    ec_point.extend(x)
    ec_point.extend(y)
    return ec_point


def _encode_public_ecdsa_key(x, y):
    """
    From https://tools.ietf.org/html/rfc5480#section-2:

    PublicKeyInfo ::= SEQUENCE {
      algorithm       AlgorithmIdentifier,
      PublicKey       BIT STRING
    }

    AlgorithmIdentifier ::= SEQUENCE {
      algorithm       OBJECT IDENTIFIER,
      parameters      ANY DEFINED BY algorithm OPTIONAL
    }
    """
    x = base64.urlsafe_b64decode(x)
    y = base64.urlsafe_b64decode(y)

    oid_curve = _object_id_curve(x)
    if oid_curve is None or len(x) != len(y):
        raise Exception(
            "X and Y must have length of either 32 (P-256), 48"
            " (P-384) or 66 (P-521) bytes but have {} and {} "
            "respectively".format(len(x), len(y))
        )

    algorithm_identifier = bytearray()
    algorithm_identifier.append(_ASN1_TAG_OBJECT_IDENTIFIER)
    algorithm_identifier.extend(_encode_length(len(_ASN1_OID_PUBKEY)))
    algorithm_identifier.extend(_ASN1_OID_PUBKEY)
    algorithm_identifier.append(_ASN1_TAG_OBJECT_IDENTIFIER)
    algorithm_identifier.extend(_encode_length(len(oid_curve)))
    algorithm_identifier.extend(oid_curve)

    algorithm = bytearray()
    algorithm.append(_ASN1_CONSTRUCTED | _ASN1_TAG_SEQUENCE)
    algorithm.extend(_encode_length(len(algorithm_identifier)))

    publickey = _encode_ec_point(x, y)

    length = len(algorithm_identifier) + len(algorithm) + len(publickey)

    publickey_info = bytearray()
    publickey_info.append(_ASN1_CONSTRUCTED | _ASN1_TAG_SEQUENCE)
    publickey_info.extend(_encode_length(length))
    publickey_info.extend(algorithm)
    publickey_info.extend(algorithm_identifier)
    publickey_info.extend(publickey)
    return bytes(publickey_info)


def _encode_private_ecdsa_key(d, x, y):
    """
    From https://tools.ietf.org/html/rfc5915#section-3

    ECPrivateKey ::= SEQUENCE {
      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      privateKey     OCTET STRING,
      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
      publicKey  [1] BIT STRING OPTIONAL
     }
    """
    d = base64.urlsafe_b64decode(d)
    x = base64.urlsafe_b64decode(x)
    y = base64.urlsafe_b64decode(y)

    oid_curve = _object_id_curve(d)
    if oid_curve is None or len(d) != len(x) or len(d) != len(y):
        raise Exception(
            "D, X and Y must have length of either 32 (P-256), 48 "
            "(P-384) or 66 (P-521) bytes but have {}, {} and {} "
            "respectively".format(len(d), len(x), len(y))
        )

    version = bytearray()
    version.append(_ASN1_TAG_INTEGER)
    version.extend(_encode_length(0x01))
    version.append(1)

    privatekey = bytearray()
    privatekey.append(_ASN1_TAG_OCTETSTRING)
    privatekey.extend(_encode_length(len(d)))
    privatekey.extend(d)

    parameters = bytearray()
    parameters.append(_ASN1_CONTEXT_SPECIFIC | _ASN1_CONSTRUCTED)  # needed for OPTIONAL [0]
    parameters.extend(_encode_length(len(oid_curve) + 2))
    parameters.append(_ASN1_TAG_OBJECT_IDENTIFIER)
    parameters.extend(_encode_length(len(oid_curve)))
    parameters.extend(oid_curve)

    pk = _encode_ec_point(x, y)
    publickey = bytearray()
    publickey.append(_ASN1_CONTEXT_SPECIFIC | _ASN1_CONSTRUCTED | 1)  # needed for OPTIONAL [1]
    publickey.extend(_encode_length(len(pk)))
    publickey.extend(pk)

    ec_privatekey = bytearray()
    ec_privatekey.append(_ASN1_CONSTRUCTED | _ASN1_TAG_SEQUENCE)
    ec_privatekey.extend(_encode_length(len(version) + len(privatekey) + len(parameters) + len(publickey)))
    ec_privatekey.extend(version)
    ec_privatekey.extend(privatekey)
    ec_privatekey.extend(parameters)
    ec_privatekey.extend(publickey)

    return bytes(ec_privatekey)
