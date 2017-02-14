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

Add `authorization_django.authorization_middleware` to the list of middlewares in `settings.py`:

::

	MIDDLEWARE = (
    	...
    	'authorization_django.authorization_middleware',
	)

__Note that `authorization_django.authorization_middleware` is [a ‘new style’
middleware](https://docs.djangoproject.com/en/1.10/topics/http/middleware/),
hence the `MIDDLEWARE` setting rather than `MIDDLEWARE_CLASSES`.__


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

	$ source env/bin/activate
	$ pip install -e .

Testing:

::

	make test
