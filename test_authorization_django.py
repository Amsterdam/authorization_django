"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import importlib
import json
import time
import types

import jwt
import pytest

from django import conf
import authorization_django
from authorization_django import jwks

JWKS = { "keys": [
    { "kty": "oct", "use": "sig", "kid": "1", "alg": "HS256", "k": "iamasymmetrickey" },
    { "kty": "oct", "use": "sig", "kid": "2", "alg": "HS384", "k": "iamanothersymmetrickey" },
    { "kty": "oct", "use": "sig", "kid": "3", "alg": "HS512", "k": "iamyetanothersymmetrickey" },
    { "kty": "EC", "use": "sig", "kid": "4", "crv": "P-256", "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=", "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=", "d":"9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk=" },
    { "kty": "EC", "use": "sig", "kid": "5", "crv": "P-384", "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J", "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy", "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd" },
    { "kty": "EC", "use": "sig", "kid": "6", "crv": "P-521", "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97", "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ", "d": "ALV2ghdOJbsaT4QFwqbOky6TwkHEC89pQ-bUe7kt5A7-8vXI2Ihi2YEtygCQ5PwtPiTxjRs5mgzVDRp5LwHyYzvn" },
    { "kty": "EC", "use": "sig", "kid": "7", "crv": "P-256", "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=", "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=" },
    { "kty": "EC", "use": "sig", "kid": "8", "crv": "P-384", "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J", "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy" },
    { "kty": "EC", "use": "sig", "kid": "9", "crv": "P-521", "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97", "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ" }
]}

TESTSETTINGS = {
    'JWKS': json.dumps(JWKS),
    'LOGGER_NAME': 'authztest'
}


conf.settings.configure(DEBUG=True)


def reload_settings(s):
    importlib.reload(authorization_django.config)
    conf.settings.DATAPUNT_AUTHZ = s


def create_token(tokendata, sign_kid, verify_kid):
    keys = jwks.load(json.dumps(JWKS))
    key = keys[sign_kid]
    return jwt.encode(tokendata, key.key, algorithm=key.alg, headers={'kid': verify_kid})


def create_request(tokendata, sign_kid, verify_kid=None, prefix='Bearer'):
    """ Django WSGI Request mock. A Django request object contains a META dict
    that contains the HTTP headers per the WSGI spec, PEP333 (meaning,
    uppercase, prefixed with HTTP_ and dashes transformed to underscores).
    """
    if verify_kid is None:
        verify_kid = sign_kid
    return types.SimpleNamespace(
        META={
            'HTTP_AUTHORIZATION': "{} {}".format(prefix, str(create_token(tokendata, sign_kid, verify_kid), 'utf-8'))
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
def tokendata_correct_scopes():
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + 30,
        'scopes': ['scope1', 'scope2']
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


def test_hmac_keys_valid(middleware, tokendata_correct_scopes):
    for kid in ("1", "2", "3"):
        request = create_request(tokendata_correct_scopes, kid)
        middleware(request)
        assert request.is_authorized_for("scope1", "scope2")


def test_ec_keys_valid(middleware, tokendata_correct_scopes):
    for sign_kid, verify_kid in (("4", "7"), ("5", "8"), ("6", "9")):
        request = create_request(tokendata_correct_scopes, sign_kid, verify_kid)
        middleware(request)
        assert request.is_authorized_for("scope1", "scope2")

"""
def test_valid_one_scope_request(middleware, tokendata_correct_scopes):
    request = create_request(
        tokendata_correct_scopes,
        TESTSETTINGS['JWT_SECRET_KEY'],
        TESTSETTINGS['JWT_ALGORITHM']
    )
    middleware(request)
    assert request.is_authorized_for("scope1")


def test_hr_authz_request(middleware, tokendata_correct_level_employee):
    request = create_request(
        tokendata_correct_level_employee,
        TESTSETTINGS['JWT_SECRET_KEY'],
        TESTSETTINGS['JWT_ALGORITHM']
    )
    middleware(request)
    assert request.is_authorized_for("HR/R")


def test_hr_scope_request(middleware, tokendata_correct_scope_hr):
    request = create_request(
        tokendata_correct_scope_hr,
        TESTSETTINGS['JWT_SECRET_KEY'],
        TESTSETTINGS['JWT_ALGORITHM']
    )
    middleware(request)
    assert request.is_authorized_for("HR/R")


def test_hr_scope_request(middleware, tokendata_correct_only_scopes):
    request = create_request(
        tokendata_correct_only_scopes,
        TESTSETTINGS['JWT_SECRET_KEY'],
        TESTSETTINGS['JWT_ALGORITHM']
    )
    middleware(request)
    assert not request.is_authorized_for("HR/R")


def test_invalid_token_requests(
        middleware, tokendata_missing_authz,
        tokendata_expired, capfd):
    requests = (
        create_request(
            tokendata_expired,
            TESTSETTINGS['JWT_SECRET_KEY'],
            TESTSETTINGS['JWT_ALGORITHM']
        ),
        create_request(
            tokendata_missing_authz,
            TESTSETTINGS['JWT_SECRET_KEY'],
            TESTSETTINGS['JWT_ALGORITHM']
        )
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
        create_request(
            tokendata_correct,
            TESTSETTINGS['JWT_SECRET_KEY'],
            TESTSETTINGS['JWT_ALGORITHM'],
            prefix='Bad'
        ),
        create_request(
            tokendata_correct,
            TESTSETTINGS['JWT_SECRET_KEY'],
            TESTSETTINGS['JWT_ALGORITHM'],
            prefix='Even Worse'
        ),
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
    assert not empty_request.is_authorized_for(
        authorization_levels.LEVEL_EMPLOYEE_PLUS)
    assert not empty_request.is_authorized_for(
        authorization_levels.LEVEL_EMPLOYEE)
    assert empty_request.is_authorized_for(
        authorization_levels.LEVEL_DEFAULT)


def test_min_scope_employee():
    authorization_django.config.settings.cache_clear()  # @UndefinedVariable
    testsettings = TESTSETTINGS.copy()
    testsettings['MIN_SCOPE'] = authorization_levels.LEVEL_EMPLOYEE
    settings.DATAPUNT_AUTHZ = testsettings
    middleware = authorization_django.authorization_middleware(lambda r: object())
    empty_request = types.SimpleNamespace(META={}, path='/', method='GET')
    response = middleware(empty_request)
    assert response.status_code == 401
    assert 'insufficient_scope' in response['WWW-Authenticate']


def test_forced_anonymous_routes():
    authorization_django.config.settings.cache_clear()  # @UndefinedVariable
    settings.DATAPUNT_AUTHZ['FORCED_ANONYMOUS_ROUTES'] = (
        '/status',
    )
    empty_request = types.SimpleNamespace(META={}, path='/status/lala', method='GET')
    middleware = authorization_django.authorization_middleware(lambda r: object())
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)


def test_options_works_while_min_scope():
    authorization_django.config.settings.cache_clear()  # @UndefinedVariable
    testsettings = TESTSETTINGS.copy()
    testsettings['MIN_SCOPE'] = authorization_levels.LEVEL_EMPLOYEE
    settings.DATAPUNT_AUTHZ = testsettings
    middleware = authorization_django.authorization_middleware(lambda r: object())
    empty_request = types.SimpleNamespace(META={}, path='/', method='OPTIONS')
    response = middleware(empty_request)
    with pytest.raises(Exception):
        response.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)


def test_unknown_config_param():
    settings.DATAPUNT_AUTHZ['lalaland'] = 'oscar'
    authorization_django.config.settings.cache_clear()  # @UndefinedVariable
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)
"""