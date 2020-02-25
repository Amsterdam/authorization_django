"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import json
import time
import types
from base64 import urlsafe_b64encode
import pytest

from jwcrypto.jwt import JWT
from django import conf

from authorization_django import authorization_middleware, config, jwks

JWKS1 = {
    "keys": [
        {
            "kty": "oct", "key_ops": ["sign", "verify"], "kid": "1", "alg": "HS256",
            "k": "aWFtYXN5bW1ldHJpY2tleQ=="
        },  # is iamasymmetrickey base64 encoded
        {
            "kty": "oct", "key_ops": ["sign", "verify"], "kid": "2",
            "alg": "HS384", "k": "aWFtYW5vdGhlcnN5bW1ldHJpY2tleQ=="
        },  # is iamanothersymmetrickey base64 encoded
        {
            "kty": "oct", "key_ops": ["sign", "verify"], "kid": "3",
            "alg": "HS512", "k": "aWFteWV0YW5vdGhlcnN5bW1ldHJpY2tleQ=="
        },  # is iamyetanothersymmetrickey base64 encoded
        {
            "kty": "EC", "key_ops": ["sign", "verify"], "kid": "4",
            "crv": "P-256", "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=",
            "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=",
            "d": "9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk="
        },
        {
            "kty": "EC", "key_ops": ["sign", "verify"], "kid": "5",
            "crv": "P-384",
            "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
            "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
            "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd"
        },
    ]
}

JWKS2 = {
    "keys": [
        {
            "kty": "EC", "key_ops": ["sign", "verify"], "kid": "6",
            "crv": "P-521",
            "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97",
            "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ",
            "d": "ALV2ghdOJbsaT4QFwqbOky6TwkHEC89pQ-bUe7kt5A7-8vXI2Ihi2YEtygCQ5PwtPiTxjRs5mgzVDRp5LwHyYzvn"
        }
    ]
}

ALG_LOOKUP = {
    "1": "HS256",
    "2": "HS384",
    "3": "HS512",
    "4": "ES256",
    "5": "ES384",
    "6": "ES512"
}

TESTSETTINGS = {
    'JWKS': json.dumps(JWKS1),
    'ALLOWED_SIGNING_ALGORITHMS': ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'],
}


conf.settings.configure(DEBUG=True)


def reload_settings(s):
    conf.settings.DATAPUNT_AUTHZ = s
    config.init_settings()
    jwks.init_keyset()


def create_token(tokendata, kid, alg):
    key = jwks.get_keyset().get_key(kid)
    token = JWT(header={"alg": alg, "kid": kid}, claims=tokendata)
    token.make_signed_token(key)
    return token


def create_unsigned_token(tokendata):
    header = urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "none"}).encode())
    tokendata = urlsafe_b64encode(json.dumps(tokendata).encode())
    return "{}.{}".format(header, tokendata)


def create_request(tokendata, kid=None, prefix='Bearer'):
    """ Django WSGI Request mock. A Django request object contains a META dict
    that contains the HTTP headers per the WSGI spec, PEP333 (meaning,
    uppercase, prefixed with HTTP_ and dashes transformed to underscores).
    """
    if not kid:
        token = create_unsigned_token(tokendata)
    else:
        token = create_token(tokendata, kid, ALG_LOOKUP[kid]).serialize()

    return types.SimpleNamespace(
        META={
            'HTTP_AUTHORIZATION': "{} {}".format(prefix, token)
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
def tokendata_correct_zero_scopes():
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + 30,
        'scopes': [],
        'sub': 'test@tester.nl',
    }


@pytest.fixture
def middleware():
    reload_settings(TESTSETTINGS)
    return authorization_middleware(lambda r: object())


def test_missing_conf():
    with pytest.raises(config.AuthzConfigurationError):
        authorization_middleware(None)


def test_bad_jwks():
    with pytest.raises(config.AuthzConfigurationError):
        reload_settings({
            'JWKS': 'iamnotajwks'
        })
        authorization_middleware(None)


def test_jwks_from_url(requests_mock, tokendata_correct):
    """ Verify that loading keyset from url works, by checking that is_authorized_for
    method correctly evaluates that user has the scopes mentioned in the token data
    """
    jwks_url = "https://get.your.jwks.here/protocol/openid-connect/certs"
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    reload_settings({
        'JWKS': None,
        'JWKS_URL': jwks_url
    })
    middleware = authorization_middleware(lambda r: object())
    request = create_request(tokendata_correct, "4")
    middleware(request)
    assert request.is_authorized_for("scope1", "scope2")


def test_reload_jwks_from_url(requests_mock, tokendata_correct):
    """ It is possible that the IdP rotates the keys. In that case the new keyset
    needs to be fetched from the JWKS url to be able to verify signed tokens.
    """
    jwks_url = "https://get.your.jwks.here/protocol/openid-connect/certs"

    # Create a request with a token signed with a key from JWKS2
    requests_mock.get(jwks_url, text=json.dumps(JWKS2))
    reload_settings({
        'JWKS': None,
        'JWKS_URL': jwks_url
    })
    assert requests_mock.call_count == 1
    request = create_request(tokendata_correct, "6")
    # Instantiate the middleware with JWKS1
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    reload_settings({
        'JWKS': None,
        'JWKS_URL': jwks_url,
        'MIN_INTERVAL_KEYSET_UPDATE': 0  # Set update interval to 0 secs for the test
    })
    assert requests_mock.call_count == 2
    middleware = authorization_middleware(lambda r: object())
    """
    Process a request with the middleware. The middleware should now:
    - refetch the keyset from jwks_url
    - receive and load JWKS1
    - still not recognize the kid
    - respond with an invalid_token response
    """
    response = middleware(request)
    assert requests_mock.call_count == 3
    assert response.status_code == 401
    assert 'WWW-Authenticate' in response
    assert 'invalid_token' in response['WWW-Authenticate']
    """
    Mock requests so jwks_url returns JWKS2 and do the same request again.
    The middleware should now:
    - refetch the keyset from jwks_url again
    - receive and load JWKS2
    - successfully verify the signature of the token
    """
    requests_mock.get(jwks_url, text=json.dumps(JWKS2))
    middleware(request)
    assert requests_mock.call_count == 4
    assert request.is_authorized_for("scope1", "scope2")


def test_hmac_keys_valid(middleware, tokendata_correct):
    for kid in ("1", "2", "3", "4", "5"):
        request = create_request(tokendata_correct, kid)
        middleware(request)
        assert request.is_authorized_for("scope1", "scope2")


def test_valid_one_scope_request(middleware, tokendata_correct):
    request = create_request(tokendata_correct, "4")
    middleware(request)
    assert request.is_authorized_for("scope1")


def test_valid_zero_scope_request(middleware, tokendata_correct_zero_scopes):
    request = create_request(tokendata_correct_zero_scopes, "4")
    middleware(request)
    assert not request.is_authorized_for("scope1")
    assert request.get_token_subject == 'test@tester.nl'


def test_get_token_subject(middleware, tokendata_correct):
    request = create_request(tokendata_correct, "4")
    middleware(request)
    assert request.get_token_subject == 'test@tester.nl'


def test_invalid_token_requests(
        middleware, tokendata_missing_scopes,
        tokendata_expired, tokendata_correct):
    reqs = (
        create_request(tokendata_expired, "4"),
        create_request(tokendata_missing_scopes, "5"),
        create_request(tokendata_correct)  # unsigned token
    )
    for request in reqs:
        response = middleware(request)
        assert response.status_code == 401
        assert 'WWW-Authenticate' in response
        assert 'invalid_token' in response['WWW-Authenticate']


def test_unknown_kid(tokendata_correct):
    """
    Verify that a token signed with an unknown key results in an "invalid_token" response
    """
    # Create a request with a token signed with a key from JWKS2
    reload_settings({
        'JWKS': json.dumps(JWKS2),
    })
    request = create_request(tokendata_correct, "6")
    # Instantiate the middleware with JWKS1
    reload_settings({
        'JWKS': json.dumps(JWKS1),
    })
    middleware = authorization_middleware(lambda r: object())
    response = middleware(request)
    assert response.status_code == 401
    assert 'WWW-Authenticate' in response
    assert 'invalid_token' in response['WWW-Authenticate']


def test_malformed_requests(middleware, tokendata_correct):
    reqs = (
        create_request(tokendata_correct, "3", prefix='Bad'),
        create_request(tokendata_correct, "2", prefix='Even Worse'),
    )
    for request in reqs:
        response = middleware(request)
        assert response.status_code == 400
        assert 'WWW-Authenticate' in response
        assert 'invalid_request' in response['WWW-Authenticate']


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
    middleware = authorization_middleware(lambda r: object())
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
    middleware = authorization_middleware(lambda r: object())
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for("scope1")


def test_options_works_while_min_scope():
    testsettings = TESTSETTINGS.copy()
    testsettings['MIN_SCOPE'] = ("scope",)
    reload_settings(testsettings)
    middleware = authorization_middleware(lambda r: object())
    empty_request = types.SimpleNamespace(META={}, path='/', method='OPTIONS')
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for("scope1")


def test_unknown_config_param():
    testsettings = TESTSETTINGS.copy()
    testsettings['lalaland'] = 'oscar'
    with pytest.raises(config.AuthzConfigurationError):
        reload_settings(testsettings)
        authorization_middleware(None)
