import json

from authorization_django.utils import get_trusted_jwks


def test_get_trusted_jwks_loads_custom_provider_and_inline_jwks(monkeypatch):
    jwks = {"keys": [{"kid": "test-key"}]}
    monkeypatch.setenv("OAUTH_TEST_URL", "https://issuer.example.test/jwks")
    monkeypatch.setenv("OAUTH_TEST_CLAIMS", "iss=https://issuer.example.test,aud=test-api")
    monkeypatch.setenv("TEST_PUBLIC_JWKS", json.dumps(jwks))

    assert get_trusted_jwks(providers=["TEST", "NON_EXISTENT"], pub_jwks="TEST_PUBLIC_JWKS") == [
        {
            "jwks_url": "https://issuer.example.test/jwks",
            "claims": {"iss": "https://issuer.example.test", "aud": "test-api"},
        },
        {"jwks": jwks, "claims": {"iss": "iss"}},
    ]


def test_get_trusted_jwks_loads_only_provider_when_pub_jwks_missing(monkeypatch):
    monkeypatch.setenv("OAUTH_TEST_URL", "https://issuer.example.test/jwks")
    monkeypatch.setenv("OAUTH_TEST_CLAIMS", "iss=https://issuer.example.test,aud=test-api")

    assert get_trusted_jwks(providers=["TEST"]) == [
        {
            "jwks_url": "https://issuer.example.test/jwks",
            "claims": {"iss": "https://issuer.example.test", "aud": "test-api"},
        },
    ]


def test_get_trusted_jwks_loads_default_providers(monkeypatch):
    monkeypatch.setenv("OAUTH_ENTRA_URL", "https://issuer.entra.test/jwks")
    monkeypatch.setenv("OAUTH_ENTRA_CLAIMS", "iss=https://issuer.entra.test,aud=test-api")
    monkeypatch.setenv("OAUTH_KEYCLOAK_URL", "https://issuer.keycloak.test/jwks")
    monkeypatch.setenv("OAUTH_KEYCLOAK_CLAIMS", "iss=https://issuer.keycloak.test,aud=test-api")

    assert get_trusted_jwks(pub_jwks="TEST_PUBLIC_JWKS") == [
        {
            "jwks_url": "https://issuer.entra.test/jwks",
            "claims": {"iss": "https://issuer.entra.test", "aud": "test-api"},
        },
        {
            "jwks_url": "https://issuer.keycloak.test/jwks",
            "claims": {"iss": "https://issuer.keycloak.test", "aud": "test-api"},
        },
    ]
