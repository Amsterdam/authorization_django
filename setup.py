""" setuptools config
"""
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    """ Custom class to avoid depending on pytest-runner.
    """
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args.split(" "))
        sys.exit(errno)


with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

version = '1.3.0'
packages = ['authorization_django']
requires = ['Django>=1.10.3', 'requests>=2.20.1', 'jwcrypto>=0.6.0']
requires_test = ['pytest>=3.0.5', 'pytest-cov>=2.4.0', 'requests_mock']
requires_extras = {
    'dev': [] + requires_test,
}

setup(
    name='datapunt-authorization-django',
    version=version,
    description='Datapunt authorization check for Django',
    url='https://github.com/Amsterdam/authorization_django',
    author='Amsterdam Datapunt',
    author_email='datapunt@amsterdam.nl',
    license='Mozilla Public License Version 2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    cmdclass={'test': PyTest},
    packages=packages,
    install_requires=requires,
    tests_require=requires_test,
    extras_require=requires_extras,
)
