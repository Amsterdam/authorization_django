import json
import os

import environ

env = environ.Env()


def get_trusted_jwks(
    providers: list[str] | None = None,
    pub_jwks: str = "PUB_JWKS",
) -> list[dict]:
    if providers is None:
        providers = ["ENTRA", "KEYCLOAK"]
    trusted_jwks = []
    for claim in providers:
        url = f"OAUTH_{claim}_URL"
        claims = f"OAUTH_{claim}_CLAIMS"
        if jwks_url := os.getenv(url):
            trusted_jwks.append(
                {
                    "jwks_url": jwks_url,
                    "claims": env.dict(claims, default={}),
                }
            )
    if jwks := os.getenv(pub_jwks):
        # Only used for testing, issuer is set to a dummy value.
        trusted_jwks.append({"jwks": json.loads(jwks), "claims": {"iss": "iss"}})
    return trusted_jwks
