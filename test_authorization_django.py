"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import json
import time
import types

import jwt
import pytest


from django import conf
import authorization_django
from authorization_django import jwks

JWKS = { "keys": [
    { "kty": "oct", "key_ops": ["sign", "verify"], "kid": "1", "alg": "HS256", "k": "aWFtYXN5bW1ldHJpY2tleQ==" },   #is iamasymmetrickey base64 encoded
    { "kty": "oct", "key_ops": ["sign", "verify"], "kid": "2", "alg": "HS384", "k": "aWFtYW5vdGhlcnN5bW1ldHJpY2tleQ==" }, #id iamanothersymmetrickey base64 encoded
    { "kty": "oct", "key_ops": ["sign", "verify"], "kid": "3", "alg": "HS512", "k": "aWFteWV0YW5vdGhlcnN5bW1ldHJpY2tleQ==" }, #is iamyetanothersymmetrickey base64 encoded
    { "kty": "EC", "key_ops": ["sign", "verify"], "kid": "4", "crv": "P-256", "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=", "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=", "d":"9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk=" },
    { "kty": "EC", "key_ops": ["sign", "verify"], "kid": "5", "crv": "P-384", "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J", "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy", "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd" },
    { "kty": "EC", "key_ops": ["sign", "verify"], "kid": "6", "crv": "P-521", "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97", "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ", "d": "ALV2ghdOJbsaT4QFwqbOky6TwkHEC89pQ-bUe7kt5A7-8vXI2Ihi2YEtygCQ5PwtPiTxjRs5mgzVDRp5LwHyYzvn" }
]}

TESTSETTINGS = {
    'JWKS': json.dumps(JWKS),
    'LOGGER_NAME': 'authztest'
}


conf.settings.configure(DEBUG=True)


def reload_settings(s):
    conf.settings.DATAPUNT_AUTHZ = s
    authorization_django.jwks._keyset = None
    authorization_django.config.init_settings()
    authorization_django.jwks.get_keyset()


def create_token(tokendata, kid):
    keys = jwks.load(JWKS)
    key = keys['signers'][kid]
    return jwt.encode(tokendata, key.key, algorithm=key.alg, headers={'kid': kid})


def create_request(tokendata, kid, prefix='Bearer'):
    """ Django WSGI Request mock. A Django request object contains a META dict
    that contains the HTTP headers per the WSGI spec, PEP333 (meaning,
    uppercase, prefixed with HTTP_ and dashes transformed to underscores).
    """
    return types.SimpleNamespace(
        META={
            'HTTP_AUTHORIZATION': "{} {}".format(prefix, str(create_token(tokendata, kid), 'utf-8'))
        },
        path='/', method='GET')


@pytest.fixture
def tokendata_missing_scopes():
    now = int(time.time())
    return {
        'exp': now + 30
    }


@pytest.fixture
def tokendata_expired():
    now = int(time.time())
    return {
        'exp': now - 5
    }


@pytest.fixture
def tokendata_correct():
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + 30,
        'scopes': ['scope1', 'scope2'],
        'sub': 'test@tester.nl',
    }


@pytest.fixture
def middleware():
    reload_settings(TESTSETTINGS)
    return authorization_django.authorization_middleware(lambda r: object())


def test_missing_conf():
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_bad_jwks():
    reload_settings({
        'JWKS': 'iamnotajwks'
    })
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_hmac_keys_valid(middleware, tokendata_correct):
    for kid in ("1", "2", "3", "4", "5", "6"):
        request = create_request(tokendata_correct, kid)
        middleware(request)
        assert request.is_authorized_for("scope1", "scope2")


def test_valid_one_scope_request(middleware, tokendata_correct):
    request = create_request(tokendata_correct, "4")
    middleware(request)
    assert request.is_authorized_for("scope1")


def test_get_token_subject(middleware, tokendata_correct):
    request = create_request(tokendata_correct, "4")
    middleware(request)
    assert request.get_token_subject == 'test@tester.nl'


def test_invalid_token_requests(
        middleware, tokendata_missing_scopes,
        tokendata_expired, capfd):
    requests = (
        create_request(tokendata_expired, "4"),
        create_request(tokendata_missing_scopes, "5"),
    )
    for request in requests:
        response = middleware(request)
        assert response.status_code == 401
        assert 'WWW-Authenticate' in response
        assert 'invalid_token' in response['WWW-Authenticate']
        _, err = capfd.readouterr()
        assert 'API authz problem' in err


def test_malformed_requests(middleware, tokendata_correct, capfd):
    requests = (
        create_request(tokendata_correct, "3", prefix='Bad'),
        create_request(tokendata_correct, "2", prefix='Even Worse'),
    )
    for request in requests:
        response = middleware(request)
        assert response.status_code == 400
        assert 'WWW-Authenticate' in response
        assert 'invalid_request' in response['WWW-Authenticate']
        _, err = capfd.readouterr()
        assert 'Invalid Authorization header' in err


def test_no_authorization_header(middleware):
    empty_request = types.SimpleNamespace(META={}, path='/', method='GET')
    middleware(empty_request)
    assert not empty_request.is_authorized_for("scope1", "scope2")
    assert not empty_request.is_authorized_for("scope1")
    assert empty_request.is_authorized_for()


def test_min_scope():
    testsettings = TESTSETTINGS.copy()
    testsettings['MIN_SCOPE'] = ("scope1",)
    reload_settings(testsettings)
    middleware = authorization_django.authorization_middleware(lambda r: object())
    empty_request = types.SimpleNamespace(META={}, path='/', method='GET')
    response = middleware(empty_request)
    assert response.status_code == 401
    assert 'insufficient_scope' in response['WWW-Authenticate']


def test_forced_anonymous_routes():
    testsettings = TESTSETTINGS.copy()
    testsettings['FORCED_ANONYMOUS_ROUTES'] = (
        '/status',
    )
    reload_settings(testsettings)
    empty_request = types.SimpleNamespace(META={}, path='/status/lala', method='GET')
    middleware = authorization_django.authorization_middleware(lambda r: object())
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for("scope1")


def test_options_works_while_min_scope():
    testsettings = TESTSETTINGS.copy()
    testsettings['MIN_SCOPE'] = ("scope",)
    reload_settings(testsettings)
    middleware = authorization_django.authorization_middleware(lambda r: object())
    empty_request = types.SimpleNamespace(META={}, path='/', method='OPTIONS')
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for("scope1")


def test_unknown_config_param():
    testsettings = TESTSETTINGS.copy()
    testsettings['lalaland'] = 'oscar'
    reload_settings(testsettings)
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)
