#!/usr/bin/env python

from setuptools import setup

py_modules = ['tokenauthz']
requires = ['Django==1.10.3', 'djangorestframework==3.5.3', 'PyJWT==1.4.2']

setup(
    name='datapunt-django-tokenauthz',
    version='0.1.0.dev1',
    description='Datapunt authorization check for Django',
    url='https://github.com/DatapuntAmsterdam/django-tokenauthz',
    author='Amsterdam Datapunt',
    author_email='datapunt.ois@amsterdam.nl',
    license='Mozilla Public License Version 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    py_modules=py_modules,
    install_requires=requires,
)
