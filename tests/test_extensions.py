from types import SimpleNamespace

import pytest

from authorization_django import authorization_middleware
from tests.test_authorization_django import TESTSETTINGS, _ok_view, create_request, reload_settings


def import_drf_extensions():
    pytest.importorskip("rest_framework")
    pytest.importorskip("drf_spectacular")

    from authorization_django.extensions.drf import HasTokenScopes, JWTAuthentication
    from authorization_django.extensions.scheme import JWTTokenScheme

    return HasTokenScopes, JWTAuthentication, JWTTokenScheme


def test_drf_jwt_authentication_returns_claims():
    _, jwt_authentication_class, _ = import_drf_extensions()
    now_claims = {
        "iat": 1,
        "exp": 2,
        "scopes": ["scope1", "scope2"],
        "sub": "test@tester.nl",
    }
    request = SimpleNamespace(get_token_claims=now_claims)

    authenticator = jwt_authentication_class()

    assert authenticator.authenticate(request) == (None, now_claims)


def test_drf_jwt_authentication_requires_claims():
    _, jwt_authentication_class, _ = import_drf_extensions()
    request = SimpleNamespace(get_token_claims=None)

    authenticator = jwt_authentication_class()

    with pytest.raises(Exception) as excinfo:
        authenticator.authenticate(request)

    assert excinfo.type.__name__ == "NotAuthenticated"
    assert "WWW-Authenticate header field" in str(excinfo.value)


def test_drf_jwt_authentication_header_uses_realm():
    _, jwt_authentication_class, _ = import_drf_extensions()
    authenticator = jwt_authentication_class()

    assert authenticator.authenticate_header(SimpleNamespace()) == 'Bearer realm="api"'


def test_has_token_scopes_uses_explicit_needed_scopes():
    permission_class, _, _ = import_drf_extensions()
    reload_settings(TESTSETTINGS)
    request = SimpleNamespace(get_token_scopes=["scope1", "scope2"])

    permission = permission_class("scope1")

    assert permission.has_permission(request, None)
    assert permission.has_object_permission(request, None, object())


def test_has_token_scopes_uses_min_scope_from_settings():
    permission_class, _, _ = import_drf_extensions()
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    tokendata_scope1 = {
        "iat": 1,
        "exp": 4102444800,
        "scopes": ["scope1"],
        "sub": "test@tester.nl",
    }
    request = create_request(tokendata_scope1, "4")
    authorization_middleware(_ok_view)(request)

    permission = permission_class()

    assert permission.has_permission(request, None)


def test_has_token_scopes_allows_when_always_ok():
    permission_class, _, _ = import_drf_extensions()
    testsettings = TESTSETTINGS.copy()
    testsettings["ALWAYS_OK"] = True
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    request = SimpleNamespace(get_token_scopes=[])

    permission = permission_class()

    assert permission.has_permission(request, None)


def test_drf_spectacular_jwt_token_scheme_definition():
    _, _, jwt_token_scheme_class = import_drf_extensions()
    scheme = jwt_token_scheme_class("authorization_django.extensions.drf.JWTAuthentication")

    assert scheme.name == "JWTAuthentication"
    assert scheme.target_class == "authorization_django.extensions.drf.JWTAuthentication"
    assert scheme.get_security_definition(None) == {"type": "http", "scheme": "bearer"}
