"""
test_authorization_django
~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import json
import time
from base64 import urlsafe_b64encode

import pytest
from django import conf
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory
from jwcrypto.jwt import JWT
from jwcrypto.common import JWException
from jwcrypto.common import JWException

from authorization_django import authorization_middleware, config, jwks
from authorization_django.exceptions import AuthorizationError, InsufficientScopeError
from authorization_django.middleware import AuthorizationMiddleware

JWKS1 = {
    "keys": [
        {
            "kty": "oct",
            "key_ops": ["sign", "verify"],
            "kid": "1",
            "alg": "HS256",
            "k": "aWFtYXN5bW1ldHJpY2tleQ==",
        },  # is iamasymmetrickey base64 encoded
        {
            "kty": "oct",
            "key_ops": ["sign", "verify"],
            "kid": "2",
            "alg": "HS384",
            "k": "aWFtYW5vdGhlcnN5bW1ldHJpY2tleQ==",
        },  # is iamanothersymmetrickey base64 encoded
        {
            "kty": "oct",
            "key_ops": ["sign", "verify"],
            "kid": "3",
            "alg": "HS512",
            "k": "aWFteWV0YW5vdGhlcnN5bW1ldHJpY2tleQ==",
        },  # is iamyetanothersymmetrickey base64 encoded
        {
            "kty": "EC",
            "key_ops": ["sign", "verify"],
            "kid": "4",
            "crv": "P-256",
            "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=",
            "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=",
            "d": "9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk=",
        },
        {
            "kty": "EC",
            "key_ops": ["sign", "verify"],
            "kid": "5",
            "crv": "P-384",
            "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
            "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
            "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd",
        },
    ]
}

JWKS2 = {
    "keys": [
        {
            "kty": "EC",
            "key_ops": ["sign", "verify"],
            "kid": "6",
            "crv": "P-521",
            "x": "AKarqFSECj9mH4scD_RSGD1lzBzomFWz63hvqDc8PkElCKByOUIo_N8jN5mpJS2RfbIj2d9bEDnpwQGLvu9kXG97",
            "y": "AF5ZmIGpat-yKHoP985gfnASPPZuhXGqPg4QdsJzdV4sY1GP45DOxwjZOmvhOzKzezmB-SSOWweMgUDNHoJreAXQ",
            "d": "ALV2ghdOJbsaT4QFwqbOky6TwkHEC89pQ-bUe7kt5A7-8vXI2Ihi2YEtygCQ5PwtPiTxjRs5mgzVDRp5LwHyYzvn",
        }
    ]
}


ALG_LOOKUP = {
    "1": "HS256",
    "2": "HS384",
    "3": "HS512",
    "4": "ES256",
    "5": "ES384",
    "6": "ES512",
}

TESTSETTINGS = {
    "JWKS": json.dumps(JWKS1),
    "ALLOWED_SIGNING_ALGORITHMS": [
        "HS256",
        "HS384",
        "HS512",
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
    ],
    "EXCEPTION_HANDLER": None,
}


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
    return f"{header}.{tokendata}"


def create_request(tokendata, kid=None, prefix="Bearer", path="/", method="GET"):
    """Django WSGI Request mock. A Django request object contains a META dict
    that contains the HTTP headers per the WSGI spec, PEP333 (meaning,
    uppercase, prefixed with HTTP_ and dashes transformed to underscores).
    """
    if not kid:
        token = create_unsigned_token(tokendata)
    else:
        token = create_token(tokendata, kid, ALG_LOOKUP[kid]).serialize()

    return RequestFactory().generic(
        method, path=path, headers={"authorization": f"{prefix} {token}"}
    )


def create_request_no_auth_header(path="/", method="GET"):
    return RequestFactory().generic(method, path)


def custom_handler(exception):
    if isinstance(exception, AuthorizationError):
        return JsonResponse({"message": "Unauthorized"}, status=401)


@pytest.fixture
def tokendata_missing_scopes():
    now = int(time.time())
    return {"exp": now + 30}


@pytest.fixture
def tokendata_expired():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now - 100,  # 60 second leeway allowed
        "scopes": ["scope1"],
    }


@pytest.fixture
def tokendata_scope1():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "scopes": ["scope1"],
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_scope2():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "scopes": ["scope2"],
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_two_scopes():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "scopes": ["scope1", "scope2"],
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_two_scopes_aud_iss():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "scopes": ["scope1", "scope2"],
        "sub": "test@tester.nl",
        "aud": "aud",
        "iss": "iss",
    }


@pytest.fixture
def tokendata_zero_scopes():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "scopes": [],
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_azure_ad_two_scopes():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "groups": ["test\\scope_1", "test\\scope_2"],
        "unique_name": "test@tester.nl",
    }


@pytest.fixture
def tokendata_entra_id_two_scopes():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "aud": "aud",
        "iss": "https://sts.windows.net",
        "roles": ["test-scope-1", "test-scope-2"],
        "unique_name": "test@tester.nl",
        "appid": "client_id",
    }


@pytest.fixture
def tokendata_keycloak_two_scopes():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "iss": "https://iam.amsterdam.nl",
        "realm_access": {"roles": ["scope_1", "scope_2"]},
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_issuer():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now + 30,
        "iss": "FOOBAR",
        "scopes": [],
        "sub": "test@tester.nl",
    }


@pytest.fixture
def tokendata_issuer_expired():
    now = int(time.time())
    return {
        "iat": now,
        "exp": now - 100,  # 60 second leeway allowed
        "iss": "FOOBAR",
        "scopes": [],
        "sub": "test@tester.nl",
    }


def _ok_view(request):
    return HttpResponse(status=200)


@pytest.fixture
def middleware():
    reload_settings(TESTSETTINGS)
    return authorization_middleware(_ok_view)


def test_missing_conf():
    with pytest.raises(config.AuthzConfigurationError):
        authorization_middleware(None)


def test_bad_jwks():
    with pytest.raises(config.AuthzConfigurationError):
        reload_settings({"JWKS": "iamnotajwks"})
        authorization_middleware(None)


def test_jwks_from_url(requests_mock, tokendata_two_scopes):
    """Verify that loading keyset from url works, by checking that is_authorized_for
    method correctly evaluates that user has the scopes mentioned in the token data
    """
    jwks_url = "https://get.your.jwks.here/protocol/openid-connect/certs"
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    reload_settings({"JWKS": None, "JWKS_URL": jwks_url})
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_two_scopes, "4")
    middleware(request)
    assert request.is_authorized_for("scope1", "scope2")


def test_jwks_from_url_entra_success(requests_mock, tokendata_two_scopes_aud_iss):
    """Verify that loading keyset from entra url works,
    by checking that aud and iss claims are present
    and is_authorized_for method correctly evaluates
    that user has the scopes mentioned in the token data
    """
    jwks_url = "https://login.microsoftonline.com/get.your.jwks.here/discovery/keys"
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    reload_settings(
        {"JWKS": None, "JWKS_URL": jwks_url, "CHECK_CLAIMS": {"aud": "aud", "iss": "iss"}}
    )
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_two_scopes_aud_iss, "4")
    middleware(request)
    assert request.is_authorized_for("scope1", "scope2")


def test_jwks_from_url_entra_error(requests_mock):
    """Verify that loading keyset from entra url raises an error when aud and iss claims are not set"""

    jwks_url = "https://login.microsoftonline.com/get.your.jwks.here/discovery/keys"
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    with pytest.raises(config.AuthzConfigurationError) as excinfo:
        reload_settings({"JWKS": None, "JWKS_URL": jwks_url})
    assert "When using Microsoft Entra ID" in str(excinfo.value)


def test_jwks_from_url_list(requests_mock, tokendata_two_scopes_aud_iss):
    """Verify that loading keyset from url list (with Keycloak and Entra keysets) works, by checking that is_authorized_for
    method correctly evaluates that user has the scopes mentioned in the token data.
    """
    kc_jwks_url = "https://get.your.jwks.here/protocol/openid-connect/certs"
    entra_jwks_url = "https://login.microsoftonline.com/get.your.jwks.here/discovery/keys"
    requests_mock.get(kc_jwks_url, text=json.dumps(JWKS1))
    requests_mock.get(entra_jwks_url, text=json.dumps(JWKS1))
    reload_settings(
        {
            "JWKS": None,
            "JWKS_URLS": [kc_jwks_url, entra_jwks_url],
            "CHECK_CLAIMS": {"aud": "aud", "iss": "iss"},
        }
    )
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_two_scopes_aud_iss, "4")
    middleware(request)
    assert request.is_authorized_for("scope1", "scope2")


def test_reload_jwks_from_url(requests_mock, tokendata_two_scopes):
    """It is possible that the IdP rotates the keys. In that case the new keyset
    needs to be fetched from the JWKS url to be able to verify signed tokens.
    """
    jwks_url = "https://get.your.jwks.here/protocol/openid-connect/certs"

    # Create a request with a token signed with a key from JWKS2
    requests_mock.get(jwks_url, text=json.dumps(JWKS2))
    reload_settings({"JWKS": None, "JWKS_URL": jwks_url})
    assert requests_mock.call_count == 1
    request = create_request(tokendata_two_scopes, "6")
    # Instantiate the middleware with JWKS1
    requests_mock.get(jwks_url, text=json.dumps(JWKS1))
    reload_settings(
        {
            "JWKS": None,
            "JWKS_URL": jwks_url,
            "MIN_INTERVAL_KEYSET_UPDATE": 0,  # Set update interval to 0 secs for the test
        }
    )
    assert requests_mock.call_count == 2, requests_mock.request_history
    middleware = authorization_middleware(lambda r: HttpResponse(status=200))
    """
    Process a request with the middleware. The middleware should now:
    - refetch the keyset from jwks_url
    - receive and load JWKS1
    - still not recognize the kid
    - respond with an invalid_token response
    """
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401
    assert requests_mock.call_count == 3
    assert e.value.code == "invalid_token"
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


def test_hmac_keys_valid(middleware, tokendata_two_scopes):
    for kid in ("1", "2", "3", "4", "5"):
        request = create_request(tokendata_two_scopes, kid)
        middleware(request)
        assert request.is_authorized_for("scope1", "scope2")


def test_keycloak_token(middleware, tokendata_keycloak_two_scopes):
    request = create_request(tokendata_keycloak_two_scopes, "1")
    middleware(request)

    assert request.get_token_subject == "test@tester.nl"
    assert request.get_token_scopes == {"SCOPE/1", "SCOPE/2"}


def test_keycloak_token_check_claims(middleware, tokendata_keycloak_two_scopes):
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"aud": "aud", "iss": "https://iam.amsterdam.nl"}
    reload_settings(testsettings)
    request = create_request(tokendata_keycloak_two_scopes, "1")
    middleware(request)

    assert request.get_token_subject == "test@tester.nl"
    assert request.get_token_scopes == {"SCOPE/1", "SCOPE/2"}


def test_entra_id_token_aud_iss(middleware, tokendata_entra_id_two_scopes):
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"aud": "aud", "iss": "https://sts.windows.net"}
    reload_settings(testsettings)
    request = create_request(tokendata_entra_id_two_scopes, "1")
    middleware(request)

    assert request.get_token_subject == "test@tester.nl"
    assert request.get_token_scopes == {"test-scope-1", "test-scope-2"}
    assert request.get_token_claims["appid"] == "client_id"


def test_entra_id_token_no_aud(middleware, tokendata_entra_id_two_scopes):
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"aud": "aud", "iss": "https://sts.windows.net"}
    reload_settings(testsettings)

    # Remove aud claim
    tokendata_entra_id_two_scopes.pop("aud", None)
    request = create_request(tokendata_entra_id_two_scopes, "1")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


@pytest.mark.xfail(reason="AD Token not supported for now")
def test_azure_ad_token(middleware, tokendata_azure_ad_two_scopes):
    request = create_request(tokendata_azure_ad_two_scopes, "1")
    middleware(request)

    assert request.get_token_subject == "test@tester.nl"
    assert request.get_token_scopes == {"SCOPE/1", "SCOPE/2"}


def test_valid_one_scope_request(middleware, tokendata_two_scopes):
    request = create_request(tokendata_two_scopes, "4")
    middleware(request)
    assert request.is_authorized_for("scope1")


def test_valid_zero_scope_request(middleware, tokendata_zero_scopes):
    request = create_request(tokendata_zero_scopes, "4")
    middleware(request)
    assert not request.is_authorized_for("scope1")
    assert request.get_token_subject == "test@tester.nl"


def test_get_token_subject(middleware, tokendata_two_scopes):
    request = create_request(tokendata_two_scopes, "4")
    middleware(request)
    assert request.get_token_subject == "test@tester.nl"


def test_get_token_scopes(middleware, tokendata_two_scopes):
    request = create_request(tokendata_two_scopes, "4")
    middleware(request)
    assert request.get_token_scopes == ["scope1", "scope2"]


def test_get_token_claims(middleware, tokendata_two_scopes):
    request = create_request(tokendata_two_scopes, "4")
    middleware(request)
    assert request.get_token_claims == tokendata_two_scopes


def test_invalid_token_requests(middleware, tokendata_missing_scopes, tokendata_two_scopes):
    reqs = (
        create_request(tokendata_missing_scopes, "5"),
        create_request(tokendata_two_scopes),  # unsigned token
    )
    for request in reqs:
        with pytest.raises(AuthorizationError) as e:
            middleware(request)
        assert e.value.status_code == 401
        assert e.value.code == "invalid_token"
        assert e.value.message == "Unauthorized"
        assert "invalid_token" in e.value.www_authenticate


def test_expired_token_request(middleware, tokendata_expired):
    # response = middleware(create_request(tokendata_expired, "4"))
    with pytest.raises(AuthorizationError) as e:
        middleware(create_request(tokendata_expired, "4"))
    assert e.value.status_code == 401
    assert e.value.message == "Unauthorized. Token expired."
    assert "expired_token" in e.value.www_authenticate


def test_unknown_kid(tokendata_two_scopes):
    """
    Verify that a token signed with an unknown key results in an "invalid_token" response
    """
    # Create a request with a token signed with a key from JWKS2
    reload_settings(
        {
            "JWKS": json.dumps(JWKS2),
        }
    )
    request = create_request(tokendata_two_scopes, "6")
    # Instantiate the middleware with JWKS1
    reload_settings(
        {
            "JWKS": json.dumps(JWKS1),
        }
    )
    middleware = authorization_middleware(_ok_view)
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401
    assert "invalid_token" in e.value.www_authenticate


def test_malformed_requests(middleware, tokendata_two_scopes):
    reqs = (
        create_request(tokendata_two_scopes, "3", prefix="Bad"),
        create_request(tokendata_two_scopes, "2", prefix="Even Worse"),
    )
    for request in reqs:
        with pytest.raises(AuthorizationError) as e:
            middleware(request)
        assert e.value.status_code == 400
        assert "invalid_request" in e.value.www_authenticate
        assert e.value.message == "Invalid Authorization header format"


def test_no_authorization_header(middleware):
    request = create_request_no_auth_header()
    middleware(request)
    assert not request.is_authorized_for("scope1", "scope2")
    assert not request.is_authorized_for("scope1")
    assert request.is_authorized_for()


def test_check_missing_iss(tokendata_scope1):
    """Enforce claim checks"""
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"iss": "FOOBAR"}
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_scope1, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


@pytest.mark.parametrize(["issuer", "expect_code"], [("NOT_FOOBAR", 401), ("FOOBAR", 200)])
def test_check_issuer(tokendata_issuer, issuer, expect_code):
    """Enforce claim checks"""
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"iss": issuer}
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_issuer, "4")
    try:
        response = middleware(request)
    except AuthorizationError as e:
        assert e.status_code == expect_code
    else:
        assert response.status_code == expect_code


def test_check_correct_issuer_expired(tokendata_issuer_expired):
    """When check_claims is given, this also overrides 'exp' checking.
    Make sure that still works!
    """
    testsettings = TESTSETTINGS.copy()
    testsettings["CHECK_CLAIMS"] = {"iss": "FOOBAR"}
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_issuer_expired, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    with pytest.raises(AuthorizationError) as e:
        middleware(create_request(tokendata_issuer_expired, "4"))
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_issuer_expired, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    with pytest.raises(AuthorizationError) as e:
        middleware(create_request(tokendata_issuer_expired, "4"))
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_issuer_expired, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    with pytest.raises(AuthorizationError) as e:
        middleware(create_request(tokendata_issuer_expired, "4"))
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_issuer_expired, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


def test_check_iss_aud_present_for_entra(tokendata_issuer_expired):
    """ """
    testsettings = TESTSETTINGS.copy()
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    with pytest.raises(AuthorizationError) as e:
        middleware(create_request(tokendata_issuer_expired, "4"))
    assert e.value.status_code == 401


def test_min_scope_sufficient(tokendata_scope1):
    """scope1 is required, scope1 is in token"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_scope1, "4")
    response = middleware(request)
    assert response.status_code == 200


def test_min_scope_insufficient():
    """scope1 is required, request with no token and default response"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request_no_auth_header()
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


@pytest.mark.parametrize(
    "request_accepts, expected_response",
    [
        (False, JsonResponse),
        (True, HttpResponse),
    ],
)
def test_min_scope_insufficient_response_type(
    request_accepts,
    expected_response,
):
    """if request.accepts("text/html") an HttpResponse should be returned"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    middleware = AuthorizationMiddleware(_ok_view)
    request = create_request_no_auth_header()
    request.accepts = lambda _: request_accepts
    exception = AuthorizationError(
        401, "Unauthorized", 'Bearer realm="datapunt", error="insufficient_scope"'
    )
    response = middleware.process_exception(request, exception)

    assert isinstance(response, expected_response)
    assert response.status_code == 401


def test_min_scope_as_string_sufficient(tokendata_scope1):
    """MIN_SCOPE configured as string instead of tuple"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = "scope1"
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_scope1, "4")
    response = middleware(request)
    assert response.status_code == 200


def test_min_scope_as_string_insufficient(tokendata_scope1):
    """MIN_SCOPE configured as string instead of tuple"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = "scope1"
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request_no_auth_header()
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401


def test_min_scope_multiple_sufficient(tokendata_two_scopes):
    """Two scopes required, both of them in token"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1", "scope2")
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_two_scopes, "4")
    response = middleware(request)
    assert response.status_code == 200


def test_min_scope_multiple_insufficient(tokendata_scope1):
    """Two scopes required, only one of them in token"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1", "scope2")
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request(tokendata_scope1, "4")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401
    assert "insufficient_scope" in e.value.www_authenticate


def test_forced_anonymous_routes(rf):
    testsettings = TESTSETTINGS.copy()
    testsettings["FORCED_ANONYMOUS_ROUTES"] = ("/status",)
    testsettings["MIN_SCOPE"] = ("scope1",)
    reload_settings(testsettings)
    empty_request = rf.get("/status/lala")
    middleware = authorization_middleware(_ok_view)
    response = middleware(empty_request)
    assert response.status_code == 200
    with pytest.raises(RuntimeError):
        empty_request.is_authorized_for("scope1")


def test_options_works_while_min_scope(rf):
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope",)
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    empty_request = rf.options(path="/")
    response = middleware(empty_request)
    assert response.status_code == 200
    with pytest.raises(RuntimeError):
        empty_request.is_authorized_for("scope1")


def test_protected_resources_all_methods(tokendata_scope1, tokendata_two_scopes):
    testsettings = TESTSETTINGS.copy()
    testsettings["PROTECTED"] = [
        ("/one_scope_required", ["*"], ["scope1"]),
        ("/two_scopes_required", ["*"], ["scope1", "scope2"]),
    ]
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)

    # a token with scope1 gives access via all methods
    # to the one_scope_required route
    for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        request = create_request(tokendata_scope1, "4", "Bearer", "/one_scope_required", method)
        response = middleware(request)
        assert request.is_authorized_for("scope1")
        assert response.status_code == 200

    # a token with only scope1 does not give access to two_scopes_required route
    request = create_request(tokendata_scope1, "4", "Bearer", "/two_scopes_required", "GET")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401
    assert "insufficient_scope" in e.value.www_authenticate

    # a token with scope1 and scope2 gives access to two_scopes_required route
    request = create_request(tokendata_two_scopes, "4", "Bearer", "/two_scopes_required", "GET")
    response = middleware(request)
    assert response.status_code == 200

    # OPTIONS method should be allowed without auth header, even with methods: *
    request = create_request_no_auth_header("/one_scope_required", "OPTIONS")
    response = middleware(request)
    assert response.status_code == 200


def test_protected_resource_read_write_distinction(tokendata_scope1, tokendata_scope2):
    testsettings = TESTSETTINGS.copy()
    testsettings["PROTECTED"] = [
        ("/read_write_distinction", ["GET", "HEAD"], ["scope1"]),
        ("/read_write_distinction", ["PATCH", "PUT", "POST", "DELETE"], ["scope2"]),
    ]
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)

    request = create_request(tokendata_scope1, "4", "Bearer", "/read_write_distinction", "GET")
    response = middleware(request)
    assert response.status_code == 200

    request = create_request(tokendata_scope1, "4", "Bearer", "/read_write_distinction", "POST")
    with pytest.raises(AuthorizationError) as e:
        middleware(request)
    assert e.value.status_code == 401
    assert "insufficient_scope" in e.value.www_authenticate

    request = create_request(tokendata_scope2, "4", "Bearer", "/read_write_distinction", "POST")
    response = middleware(request)
    assert response.status_code == 200


def test_unknown_config_param():
    testsettings = TESTSETTINGS.copy()
    testsettings["lalaland"] = "oscar"
    with pytest.raises(config.AuthzConfigurationError):
        reload_settings(testsettings)
        authorization_middleware(None)


def test_protected_resource_syntax_error():
    invalid_entries = [
        ("foo",),
        ("/foo",),
        ("/foo", ["*"]),
    ]
    for entry in invalid_entries:
        testsettings = TESTSETTINGS.copy()
        protected = []
        protected.append(entry)
        testsettings["PROTECTED"] = protected
        with pytest.raises(config.ProtectedRecourceSyntaxError):
            reload_settings(testsettings)
            authorization_middleware(None)


def test_empty_scopes_error():
    testsettings = TESTSETTINGS.copy()
    testsettings["PROTECTED"] = [("/foo/protected", ["*"], [])]
    with pytest.raises(config.NoRequiredScopesError):
        reload_settings(testsettings)
        authorization_middleware(None)


def test_protected_route_overruled_error():
    """Configuring a protected route that would be overruled by a
    route in FORCED_ANONYMOUS_ROUTES should lead to a ProtectedRouteConflict
    """
    testsettings = TESTSETTINGS.copy()
    testsettings["PROTECTED"] = [("/foo/protected", ["*"], ["scope1"])]
    testsettings["FORCED_ANONYMOUS_ROUTES"] = ("/foo",)
    with pytest.raises(config.ProtectedRouteConflictError):
        reload_settings(testsettings)
        authorization_middleware(None)


def test_custom_exception():
    """test custom handler"""
    testsettings = TESTSETTINGS.copy()
    testsettings["MIN_SCOPE"] = ("scope1",)
    testsettings["EXCEPTION_HANDLER"] = custom_handler
    reload_settings(testsettings)
    middleware = authorization_middleware(_ok_view)
    request = create_request_no_auth_header()
    with pytest.raises(InsufficientScopeError) as e:
        middleware(request)
    assert e.value.status_code == 401
