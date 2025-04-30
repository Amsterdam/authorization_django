"""setuptools config"""

from setuptools import setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

version = "1.6.0"
packages = [
    "authorization_django",
    "authorization_django.extensions",
]
requires = [
    "Django>=4.2",
    "requests>=2.32.3",
    "jwcrypto>=1.5.6",
]
tests_require = [
    "pytest>=8.3.5",
    "pytest-cov>=6.0.0",
    "pytest-django>=4.10.0",
    "requests_mock",
]
extended_require = [
    "djangorestframework>=3.15.2",
    "drf-spectacular>=0.28.0",
]

setup(
    name="datapunt-authorization-django",
    version=version,
    description="Datapunt authorization check for Django",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Amsterdam/authorization_django",
    author="Amsterdam Datapunt",
    author_email="datapunt@amsterdam.nl",
    license="Mozilla Public License Version 2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=packages,
    install_requires=requires,
    extras_require={
        "tests": tests_require,
        "extended": extended_require + tests_require,
    },
)
