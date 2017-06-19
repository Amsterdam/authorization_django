"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import time
import types

import jwt
import pytest

from django.conf import settings
import authorization_django
from authorization_django import levels as authorization_levels

TESTSETTINGS = {
    'JWT_SECRET_KEY': '0123456789012345',
    'JWT_ALGORITHM': 'HS256',
    'LOGGER_NAME': 'authztest'
}


settings.configure(DEBUG=True)


def create_request(tokendata, key, alg, prefix='Bearer'):
    """ Django WSGI Request mock. A Django request object contains a META dict
    that contains the HTTP headers per the WSGI spec, PEP333 (meaning,
    uppercase, prefixed with HTTP_ and dashes transformed to underscores).
    """
    return types.SimpleNamespace(
        META={
            'HTTP_AUTHORIZATION': "{} {}".format(prefix, str(
                jwt.encode(tokendata, key, algorithm=alg), 'utf-8'))
        },
        path='/', method='GET')


@pytest.fixture
def tokendata_correct():
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + 30,
        'authz': authorization_levels.LEVEL_EMPLOYEE_PLUS
    }


@pytest.fixture
def tokendata_missing_authz():
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + 30
    }


@pytest.fixture
def tokendata_expired():
    now = int(time.time())
    return {
        'iat': now - 10,
        'exp': now - 5
    }


@pytest.fixture
def middleware():
    settings.DATAPUNT_AUTHZ = TESTSETTINGS
    return authorization_django.authorization_middleware(lambda r: object())


def test_missing_jwt_conf():
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_bad_jwt_key():
    settings.DATAPUNT_AUTHZ = {
        'JWT_SECRET_KEY': '01234567',  # <- too short
        'JWT_ALGORITHM': 'HS256'
    }
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_bad_jwt_algorithm():
    settings.DATAPUNT_AUTHZ = {
        'JWT_SECRET_KEY': '0123456789012345',  # <- too short
        'JWT_ALGORITHM': 'RSA'
    }
    with pytest.raises(authorization_django.config.AuthzConfigurationError):
        authorization_django.authorization_middleware(None)


def test_valid_request(middleware, tokendata_correct):
    request = create_request(
        tokendata_correct,
        TESTSETTINGS['JWT_SECRET_KEY'],
        TESTSETTINGS['JWT_ALGORITHM']
    )
    middleware(request)
    assert request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)


def test_invalid_token_requests(
        middleware, tokendata_correct, tokendata_missing_authz,
        tokendata_expired, capfd):
    requests = (
        create_request(
            tokendata_correct,
            'INVALID_KEY',
            TESTSETTINGS['JWT_ALGORITHM']
        ),
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
