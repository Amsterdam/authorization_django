"""
authorization_middleware.config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import logging
from collections.abc import Callable, Iterator, Mapping

from django.conf import settings as django_settings
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

logger = logging.getLogger(__name__)

MICROSOFT = "https://login.microsoftonline.com/"


class Claims(BaseModel):
    iss: str
    aud: str | list[str] | None = None


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
    JWKS: str | None = ""
    JWKS_URL: str | None = ""
    JWKS_URLS: list[str] = Field(default_factory=list)
    CHECK_CLAIMS: dict = Field(default_factory=dict)
    TRUSTED_JWKS: list[TrustedJwksItem] = Field(default_factory=list)
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

    @property
    def effective_jwks_url(self):
        try:
            return next(item.jwks_url for item in self.TRUSTED_JWKS if item.jwks_url)
        except StopIteration:
            return self.JWKS_URL

    @property
    def effective_jwks_urls(self):
        if self.TRUSTED_JWKS:
            trusted_urls = [item.jwks_url for item in self.TRUSTED_JWKS if item.jwks_url]
            if trusted_urls:
                return trusted_urls
        return self.JWKS_URLS

    @property
    def effective_check_claims(self):
        for item in self.TRUSTED_JWKS:
            if item.claims:
                return item.claims.model_dump(exclude_none=True)
        return self.CHECK_CLAIMS

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
        if not self.JWKS and not self.effective_jwks_url and not self.effective_jwks_urls:
            raise AuthzConfigurationError(
                f"{SETTINGS_KEY}['JWKS'], {SETTINGS_KEY}['JWKS_URL'] or {SETTINGS_KEY}['JWKS_URLS']  must be set, or all"
            )

        is_entra = (
            self.effective_jwks_url and self.effective_jwks_url.startswith(MICROSOFT)
        ) or any(url.startswith(MICROSOFT) for url in self.effective_jwks_urls)
        if is_entra and {"iss", "aud"}.isdisjoint(self.effective_check_claims):
            raise AuthzConfigurationError(
                "When using Microsoft Entra ID, make sure to set an 'iss' and 'aud' claim"
                f" in the {SETTINGS_KEY}['TRUSTED_JWKS'] settings for entra."
            )

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


class SettingsProxy(Mapping):
    """Read-only settings wrapper with deprecated-setting compatibility."""

    _deprecated_keys = {"JWKS_URL", "JWKS_URLS", "CHECK_CLAIMS"}

    def __init__(self, settings: Settings):
        self._values = settings.model_dump()
        self._values["TRUSTED_JWKS"] = [
            item.model_dump(exclude_none=True) for item in settings.TRUSTED_JWKS
        ]
        self._values["PROTECTED"] = [
            (resource.route, resource.methods, resource.scopes) for resource in settings.PROTECTED
        ]
        # Warn if any deprecated keys are present in the initial values
        deprecated_keys = self._deprecated_keys & self._values.keys()
        if deprecated_keys:
            logger.warning(
                "Deprecated settings present: %s. Please migrate to TRUSTED_JWKS.",
                ", ".join(sorted(deprecated_keys)),
            )

    def __getitem__(self, key):
        if key in self._deprecated_keys:
            logger.warning("Accessing deprecated setting %s. Please migrate to TRUSTED_JWKS.", key)
            trusted_value = self._trusted_jwks_value(key)
            if trusted_value is not None:
                return trusted_value
        if key == "TRUSTED_JWKS":
            if self._values["TRUSTED_JWKS"]:
                return self._values["TRUSTED_JWKS"]
            logger.warning(
                "TRUSTED_JWKS is not set, constructing from JWKS, JWKS_URLS, JWKS_URL, and CHECK_CLAIMS."
            )
            logger.warning("This will be deprecated in v3.0.0")
            return self._compose_trusted_jwks()
        return self._values[key]

    def _compose_trusted_jwks(self):
        trusted_jwks = []
        check_claims = self._values.get("CHECK_CLAIMS")
        check_claims_no_aud = {k: v for k, v in (check_claims or {}).items() if k != "aud"}
        if self._values["JWKS"]:
            trusted_jwks.append(
                {
                    "jwks": self._values["JWKS"],
                    "claims": check_claims_no_aud,
                }
            )
        if self._values["JWKS_URLS"]:
            trusted_jwks.extend(
                {
                    "jwks_url": url,
                    "claims": check_claims if url.startswith(MICROSOFT) else check_claims_no_aud,
                }
                for url in self._values["JWKS_URLS"]
            )
        if self._values["JWKS_URL"]:
            trusted_jwks.append(
                {
                    "jwks_url": self._values["JWKS_URL"],
                    "claims": check_claims
                    if self._values["JWKS_URL"].startswith(MICROSOFT)
                    else check_claims_no_aud,
                }
            )
        return trusted_jwks

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def _trusted_jwks_value(self, key):
        trusted_jwks = self._values.get("TRUSTED_JWKS") or []
        if not trusted_jwks:
            return None

        if key == "JWKS_URL":
            return trusted_jwks[0].get("jwks_url")

        if key == "JWKS_URLS":
            return [item["jwks_url"] for item in trusted_jwks if item.get("jwks_url")] or None

        if key == "CHECK_CLAIMS":
            try:
                return next(item["claims"] for item in trusted_jwks if item.get("claims"))
            except StopIteration:
                return None
        return None


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
        settings = Settings.model_validate(user_settings, extra="forbid")
    except ValidationError as e:
        raise AuthzConfigurationError(f"Invalid {SETTINGS_KEY} configuration: {e}") from e

    return SettingsProxy(settings)
