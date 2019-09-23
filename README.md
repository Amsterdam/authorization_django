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
| FORCED_ANONYMOUS_ROUTES | Routes for which not to check for authorization| empty tuple |
| ALWAYS_OK | Disable any authorization checks, use only for local development| False |
| ALLOWED_SIGNING_ALGORITHMS | List of allowed algorithms for signing web tokens | ['HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512']|

Usage
-----

The middleware will add a callable `request.is_authorized_for(authz_level)`
that will tell you whether the current request is authorized for the given
`authz_level`:

```
import authorization_django

if request.is_authorized_for(authorization_django.levels.LEVEL_EMPLOYEE_PLUS):
  ...  # return super secret things
elif request.is_authorized_for(authorization_django.levels.LEVEL_EMPLOYEE):
  ...  # return a little less secret things
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
