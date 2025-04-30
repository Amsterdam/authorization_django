"""
authorization_middleware.config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import types

from django.conf import settings as django_settings

# The Django settings key
_settings_key = "DATAPUNT_AUTHZ"

# A list of all available settings, with default values
_available_settings = {
    "JWKS": "",
    "JWKS_URL": "",
    "JWKS_URLS": [],
    "ALLOWED_SIGNING_ALGORITHMS": [
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
    ],
    "CHECK_CLAIMS": {},
    "MIN_SCOPE": (),
    "PROTECTED": [],
    "ALWAYS_OK": False,
    "FORCED_ANONYMOUS_ROUTES": (),
    "MIN_INTERVAL_KEYSET_UPDATE": 30,
}

_methods_valid_options = ["*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE"]

_settings = {}

# Preprocessing: the set of all available configuration keys
_available_settings_keys = set(_available_settings.keys())


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
    user_settings = dict(getattr(django_settings, _settings_key, {}))
    user_settings_keys = set(user_settings.keys())

    # Check for unknown settings
    unknown = user_settings_keys - _available_settings_keys
    if unknown:
        raise AuthzConfigurationError(f"Unknown {_settings_key} config params: {unknown}")

    # Merge defaults with provided settings
    missing_defaults = _available_settings_keys - user_settings_keys
    user_settings.update({key: _available_settings[key] for key in missing_defaults})

    _validate_values(user_settings)
    return types.MappingProxyType(user_settings)


def _validate_values(user_settings: dict):
    if not user_settings["JWKS"] and not user_settings["JWKS_URL"]:
        raise AuthzConfigurationError(
            f"Either {_settings_key}['JWKS'] or {_settings_key}['JWKS_URL'] must be set, or both"
        )

    is_entra = (
        user_settings["JWKS_URL"]
        and user_settings["JWKS_URL"].startswith("https://login.microsoftonline.com/")
    ) or any(
        url.startswith("https://login.microsoftonline.com/") for url in user_settings["JWKS_URLS"]
    )
    if is_entra and {"iss", "aud"}.isdisjoint(user_settings["CHECK_CLAIMS"]):
        # As tokens handed out by Entra ID can come from other instances,
        # checking the issuer and audience is super important!
        raise AuthzConfigurationError(
            "When using Microsoft Entra ID, make sure to set an 'iss' and 'aud' claim"
            f" in the {_settings_key}['CHECK_CLAIMS'] setting"
        )

    if isinstance(user_settings["MIN_SCOPE"], str):
        user_settings["MIN_SCOPE"] = (user_settings["MIN_SCOPE"],)

    if not isinstance(user_settings["FORCED_ANONYMOUS_ROUTES"], (list, tuple, set)):
        raise AuthzConfigurationError(
            f"{_settings_key}['FORCED_ANONYMOUS_ROUTES'] must be a list, tuple or set"
        )

    if not isinstance(user_settings["PROTECTED"], (list, tuple, set)):
        raise AuthzConfigurationError(f"{_settings_key}['PROTECTED'] must be a list, tuple or set")

    for resource in user_settings["PROTECTED"]:
        if not isinstance(resource, tuple) or not len(resource) == 3:
            raise ProtectedRecourceSyntaxError(
                f"Resource in {_settings_key}['PROTECTED'] must be a tuple of length 3"
            )

        (route, methods, scopes) = resource
        _validate_protected_route(route, user_settings)
        _validate_protected_methods(methods)
        _validate_protected_scopes(scopes, route)


def _validate_protected_route(route, user_settings):
    """Validate 'route' in PROTECTED block."""
    if not isinstance(route, str):
        raise AuthzConfigurationError(
            f"Route in {_settings_key}['PROTECTED'] resource must be a string"
        )

    for aroute in user_settings["FORCED_ANONYMOUS_ROUTES"]:
        if route.startswith(aroute):
            raise ProtectedRouteConflictError(
                f"{route} is configured in {_settings_key}['PROTECTED'], but this would be "
                f"overruled by {aroute} in {_settings_key}['FORCED_ANONYMOUS_ROUTES']"
            )


def _validate_protected_methods(methods):
    """Validate 'methods' in PROTECTED block."""
    if not isinstance(methods, list):
        raise AuthzConfigurationError(
            f"Methods in {_settings_key}['PROTECTED'] resource must be a list"
        )

    for method in methods:
        if method not in _methods_valid_options:
            str_methods = ", ".join(_methods_valid_options)
            raise AuthzConfigurationError(
                f"Invalid value for methods: {method} in {_settings_key}['PROTECTED']."
                f" Must be one of {str_methods}."
            )


def _validate_protected_scopes(scopes, route):
    """Validate 'scopes' in PROTECTED block."""
    if not isinstance(scopes, list):
        raise AuthzConfigurationError(
            f"Scopes in {_settings_key}['PROTECTED'] resource must be a list"
        )

    if not len(scopes) > 0:
        raise NoRequiredScopesError(
            f"You must require at least one scope for protected route {route} in {_settings_key}['PROTECTED']"
        )
