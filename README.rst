Datapunt Django Authorization
=============================

.. image:: https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg
    :target: https://www.python.org/

.. image:: https://img.shields.io/badge/license-MPLv2.0-blue.svg
    :target: https://www.mozilla.org/en-US/MPL/2.0/

---------------------

Install
-------

Install the Django middleware:

::

	pip install datapunt-authorization-django

... and add it to your requirements.txt.

Add `authorization_django.authorization_middleware` to the list of middlewares
in `settings.py`, and add the JWT secret and algorithm.

    **NOTE** ``authorization_django.authorization_middleware`` is [a ‘new style’
    middleware](https://docs.djangoproject.com/en/1.10/topics/http/middleware/).
    Make sure to add it to the ``MIDDLEWARE`` setting, **NOT** to the
    ``MIDDLEWARE_CLASSES`` setting.

::

	MIDDLEWARE = (
    	...
    	'authorization_django.authorization_middleware',
	)



Settings
--------

The following settings are used by the middleware, and can be configured in
your ``settings.py`` in the ``DATAPUNT_AUTHZ`` dictionary.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_SECRET_KEY``                (Required) Your JWT signing key
``JWT_ALGORITHM``                 (Required) Algorithm to use for the JWT
                                  message authentication code (MAC)
``MIN_SCOPE``                     Minimum needed scope (Default = 
                                  ``authorization_levels.LEVEL_DEFAULT``)
``LOGGER_NAME``                   Name of the logger. (Default =
                                  ``authorization_django``)
``LOGGER_HANDLER_POLICY``         the policy of the default logging
                                  handler.  The default is ``'always'``
                                  which means that the default logging
                                  handler is always active.  ``'debug'``
                                  will only activate logging in debug
                                  mode, ``'production'`` will only log in
                                  production and ``'never'`` disables it
                                  entirely.
``LOGGER_FORMAT_PROD``            Log format for production messages
``LOGGER_FORMAT_DEBUG``           Log format for debug messages


Usage
-----

The middleware will add a callable `request.is_authorized_for(authz_level)`
that will tell you whether the current request is authorized for the given
`authz_level`:

::

	import authorization_django

	if request.is_authorized_for(authorization_django.levels.LEVEL_EMPLOYEE_PLUS):
		...  # return super secret things
	elif request.is_authorized_for(authorization_django.levels.LEVEL_EMPLOYEE):
		...  # return a little less secret things
	else:
		...  # only the public stuff

Contribute
----------

Activate your virtualenv, install the egg in `editable` mode, and start coding:

::

	$ pip install -e .

Testing:

::

	make test


Changelog
---------

- v0.2.3 (to be released)

  * Settings are now grouped in settings.py (see Settings section above)
  * Middleware now creates audit logs
