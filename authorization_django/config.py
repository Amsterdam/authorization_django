"""
authorization_middleware.config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import logging
from collections.abc import Callable
from time import time

from django.conf import settings as django_settings
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    computed_field,
    field_validator,
    model_validator,
)

logger = logging.getLogger(__name__)

MICROSOFT = "https://login.microsoftonline.com/"


class Claims(BaseModel):
    iss: str
    aud: str | list[str] | None = None

    @computed_field
    @property
    def exp(self) -> int:
        return int(time())


class TrustedJwksItem(BaseModel):
    jwks_url: str | None = None
    jwks: dict | None = None
    claims: Claims

    @model_validator(mode="after")
    def validate(self):
        if not self.jwks_url and not self.jwks:
            raise AuthzConfigurationError("Either jwks_url or jwks must be provided")
        if self.jwks_url and self.jwks:
            raise AuthzConfigurationError("Provide either jwks_url or jwks, not both")
        if self.jwks_url and self.jwks_url.startswith(MICROSOFT) and not self.claims.aud:
            raise AuthzConfigurationError(
                "When using Microsoft Entra ID, make sure to set an 'iss' and 'aud' claim"
                f" in the {SETTINGS_KEY}['TRUSTED_JWKS'] settings for entra."
            )
        return self


class ProtectedResource(BaseModel):
    route: str
    methods: list[str]
    scopes: list[str]

    @field_validator("methods")
    def validate_methods(cls, value):
        for method in value:
            if method not in VALID_METHODS:
                str_methods = ", ".join(VALID_METHODS)
                raise ValueError(
                    f"Invalid value for methods: {method} in {SETTINGS_KEY}['PROTECTED']."
                    f" Must be one of {str_methods}."
                )
        return value

    @field_validator("scopes")
    def validate_scopes(cls, value, info):
        route = info.data.get("route", "<unknown>")
        if not value:
            raise NoRequiredScopesError(
                f"You must require at least one scope for protected route {route} in {SETTINGS_KEY}['PROTECTED']"
            )
        return value

    @classmethod
    def from_raw(cls, resource):
        if not isinstance(resource, tuple) or len(resource) != 3:
            raise ProtectedRecourceSyntaxError(
                f"Resource in {SETTINGS_KEY}['PROTECTED'] must be a tuple of length 3"
            )

        route, methods, scopes = resource
        try:
            protected_resource = cls.model_validate(
                {
                    "route": route,
                    "methods": methods,
                    "scopes": scopes,
                }
            )
        except ValidationError as e:
            message = e.errors()[0]["msg"]
            raise AuthzConfigurationError(
                f"Invalid {SETTINGS_KEY} configuration: {message}"
            ) from e

        return protected_resource


class Settings(BaseModel):
    TRUSTED_JWKS: list[TrustedJwksItem] = Field(default_factory=list, min_length=1)
    ALLOWED_SIGNING_ALGORITHMS: list[str] = Field(
        default_factory=lambda: [
            "ES256",
            "ES384",
            "ES512",
            "RS256",
            "RS384",
            "RS512",
        ]
    )
    MIN_SCOPE: tuple = Field(default_factory=tuple)
    PROTECTED: list = Field(default_factory=list)
    ALWAYS_OK: bool = False
    FORCED_ANONYMOUS_ROUTES: tuple = Field(default_factory=tuple)
    MIN_INTERVAL_KEYSET_UPDATE: int = 30
    EXCEPTION_HANDLER: Callable | None = None

    @field_validator("MIN_SCOPE", mode="before")
    def validate_min_scope(cls, v):
        if type(v) is not tuple:
            return (v,)
        return v

    @field_validator("FORCED_ANONYMOUS_ROUTES", mode="before")
    def validate_forced_anonymous_routes(cls, value):
        if not isinstance(value, (list, tuple, set)):
            raise ValueError(
                f"{SETTINGS_KEY}['FORCED_ANONYMOUS_ROUTES'] must be a list, tuple or set"
            )
        return tuple(value)

    @field_validator("PROTECTED", mode="before")
    def validate_protected(cls, value):
        if not isinstance(value, (list, tuple, set)):
            raise ValueError(f"{SETTINGS_KEY}['PROTECTED'] must be a list, tuple or set")
        return [ProtectedResource.from_raw(resource) for resource in value]

    @model_validator(mode="after")
    def validate_model(self):
        for resource in self.PROTECTED:
            for anonymous_route in self.FORCED_ANONYMOUS_ROUTES:
                if resource.route.startswith(anonymous_route):
                    raise ProtectedRouteConflictError(
                        f"{resource.route} is configured in {SETTINGS_KEY}['PROTECTED'], but this would be "
                        f"overruled by {anonymous_route} in {SETTINGS_KEY}['FORCED_ANONYMOUS_ROUTES']"
                    )

        return self


# The Django settings key
SETTINGS_KEY = "DATAPUNT_AUTHZ"

VALID_METHODS = ["*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE"]

_settings = {}


class AuthzConfigurationError(Exception):
    """Error for missing / invalid configuration"""


class ProtectedRouteConflictError(AuthzConfigurationError):
    """Error for a conflicting protected route configuration"""


class ProtectedRecourceSyntaxError(AuthzConfigurationError):
    """Syntax error in configuration of protected resource"""


class NoRequiredScopesError(AuthzConfigurationError):
    """Error for when route is configured as protected
    but no required scopes have been set
    """


def init_settings():
    global _settings
    _settings = load_settings()


def get_settings():
    global _settings
    if not _settings:
        init_settings()
    return _settings


def load_settings():
    """Fetch the middleware settings.

    :return dict: settings
    """
    # Get the user-provided settings
    user_settings = dict(getattr(django_settings, SETTINGS_KEY, {}))

    try:
        return Settings.model_validate(user_settings, extra="forbid")
    except ValidationError as e:
        raise AuthzConfigurationError(f"Invalid {SETTINGS_KEY} configuration: {e}") from e
