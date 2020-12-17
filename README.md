Datapunt Django Authorization
=============================

![python 3.4 onward](https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg)
![Mozilla Public License Version 2.0](https://img.shields.io/badge/license-MPLv2.0-blue.svg)

Django middleware that adds functionality to check authorization, based on JSON Web Tokens.

---------------------

Install
-------

Install the Django middleware:
```
pip install datapunt-authorization-django
```

Add `authorization_django.authorization_middleware` to the list of middlewares
in `settings.py`, and configure either a JWKS as json or a url to a JWKS.

```
MIDDLEWARE = (
   ...
   'authorization_django.authorization_middleware',
)
```

Settings
--------

The following settings are used by the middleware, and can be configured in
your ``settings.py`` in the ``DATAPUNT_AUTHZ`` dictionary.

| Setting | Description | Default value |
| ------- | ----------- | ------------- |
| JWKS | A valid JWKS as json, to validate tokens. See RFC 7517 and 7518 for details | "" |
| JWKS_URL | A url to a valid JWKS, to validate tokens | "" |
| MIN_INTERVAL_KEYSET_UPDATE | Minimal interval in secs between two checks for keyset update | 30 |
| MIN_SCOPE | Minimum needed scope(s) to view non-whitelisted urls | empty tuple |
| FORCED_ANONYMOUS_ROUTES | Routes for which not to check for authorization (whitelist)| empty tuple |
| PROTECTED | Routes which require scopes for access. Optionally with distinction of methods | empty list |
| ALWAYS_OK | Disable any authorization checks, use only for local development| False |
| ALLOWED_SIGNING_ALGORITHMS | List of allowed algorithms for signing web tokens | ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512']|

Usage
-----

The middleware provides different ways to add authorization to the application:

#### Define a minimal scope that is required for access
With the MIN_SCOPE setting you can define a tuple of scopes that are required to access the application. An exception is made for the routes defined in FORCED_ANONYMOUS_ROUTES, which is basically a whitelist, and for the OPTIONS method, which is always allowed. It is also allowed to configure a single scope as a string.
```
# Require 'employee' scope for access, except for /status route
'MIN_SCOPE': 'employee'
'FORCED_ANONYMOUS_ROUTES': '/status'
```
or e.g.
```
# Require 'employee' and 'hr' scope for access
'MIN_SCOPE': ('employee', 'hr')
```

#### Define protected routes
With the PROTECTED setting you can define routes that require certain scopes for access. A distinction can be made between HTTP methods. An exception is made for the OPTIONS method, which is always allowed.
```
# Require 'employee' scope for access to /api/secure route
'PROTECTED': [
  ('/api/secure', ['*'], ['employee'])
]
```
```
# Require 'employee' scope for read access to /private route
# Require 'admin' scope for write access to /private route
'PROTECTED': [
  ('/private', ['GET', 'HEAD'], 'employee')
  ('/private', ['POST', 'PUT', 'PATCH', 'DELETE'])
]
```
**Note:** the FORCED_ANONYMOUS_ROUTES setting takes precedence over the routes defined in PROTECTED, so if a route in PROTECTED starts with a route set in FORCED_ANONYMOUS_ROUTES, this will lead to a ProtectedRouteConflictError

#### A method to check for authorization is added to the request object
It will add a callable `request.is_authorized_for(authz_level)`
that can tell you whether the current request is authorized for the given
`authz_level`:

```
if request.is_authorized_for('level_admin'):
  ...  # do admin things
elif request.is_authorized_for('level_employee'):
  ...  # do employee level things
else:
  ...  # only the public stuff
```

Contribute
----------

Activate your virtualenv, install the egg in `editable` mode, and start coding:
```
$ pip install -e .
```

Testing:
```
make test
```

Changelog
---------
- v1.3.0
  * Support Microsoft Azure AD JWT Token structure
- v1.2.0:
  * expose claims via get_token_claims
- v1.1.0
  * Expose scopes via get_token_scopes
  * Fix SyntaxWarning in middleware
  * Add option to require authorization for specific routes
  * Fix MIN_SCOPE as tuple bug
- v1.0.0
  * By default do not allow symmetric signing algoritms
- v0.3.1
  * Bugfix for token with empty scopes claim
  * Lowered version requirement for requests module
- v0.3
  * Use jwcrypto module to verify tokens
  * Add support to load JWKS from public url
  * Remove support for custom logger settings
- v0.2.3
  * Settings are now grouped in settings.py (see Settings section above)
  * Middleware now creates audit logs
