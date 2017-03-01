"""
    test_authorization_django
    ~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import time
import types

import jwt
import pytest

import authorization_django
from django.conf import settings
from django.core import exceptions

from authorization_django import levels as authorization_levels

TESTSETTINGS = {
    'JWT_SECRET_KEY': 'testkey',
    'JWT_ALGORITHM': 'HS256'
}


def create_request(tokendata, key, alg, prefix='Bearer'):
    return types.SimpleNamespace(META={
        'HTTP_AUTHORIZATION': "{} {}".format(prefix, str(
            jwt.encode(tokendata, key, algorithm=alg), 'utf-8'))
    })

now = int(time.time())

tokendata_correct = {
    'iat': now,
    'exp': now + 30,
    'authz': authorization_levels.LEVEL_EMPLOYEE_PLUS
}
tokendata_expired = {
    'iat': now - 10,
    'exp': now - 5
}

correct_request = create_request(
    tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM']
)

expired_token_request = create_request(
    tokendata_expired, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM']
)

invalid_token_request = create_request(
    tokendata_correct, 'INVALID_KEY', TESTSETTINGS['JWT_ALGORITHM']
)

malformed_requests = (
    create_request(
        tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM'], prefix='Bad'
    ),
    create_request(
        tokendata_correct, TESTSETTINGS['JWT_SECRET_KEY'], TESTSETTINGS['JWT_ALGORITHM'], prefix='Even Worse'
    ),
)

settings.configure(**TESTSETTINGS)


def get_response(request):
    return True

middleware = authorization_django.authorization_middleware(get_response)


def test_valid_request():
    middleware(correct_request)
    assert correct_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)


def test_expired_token_request():
    with pytest.raises(exceptions.SuspiciousOperation):
        middleware(expired_token_request)


def test_invalid_token_request():
    with pytest.raises(exceptions.SuspiciousOperation):
        middleware(invalid_token_request)


def test_malformed_request():
    for malformed_request in malformed_requests:
        with pytest.raises(exceptions.SuspiciousOperation):
            middleware(malformed_request)


def test_no_authorization_header():
    empty_request = types.SimpleNamespace(META={})
    middleware(empty_request)
    assert not empty_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE_PLUS)
    assert not empty_request.is_authorized_for(authorization_levels.LEVEL_EMPLOYEE)
    assert empty_request.is_authorized_for(authorization_levels.LEVEL_DEFAULT)
