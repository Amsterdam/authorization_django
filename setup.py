""" setuptools config
"""
import sys

from setuptools import setup

with open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

version = '0.2.16'
packages = ['authorization_django']
requires = ['Django>=1.10.3', 'PyJWT>=1.5.2', 'cryptography==2.1.2']
requires_test = ['pytest==3.0.5', 'pytest-cov==2.4.0']
requires_extras = {
    'dev': [] + requires_test,
}

setup(
    name='datapunt-authorization-django',
    version=version,
    description='Datapunt authorization check for Django',
    url='https://github.com/Amsterdam/authorization_django',
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
    packages=packages,
    install_requires=requires,
    tests_require=requires_test,
    extras_require=requires_extras,
)
