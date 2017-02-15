""" setuptools config
"""

from setuptools import setup

version = '0.2.0'
py_modules = ['authorization_django']
requires = ['datapunt-authorization-levels', 'Django>=1.10.3', 'PyJWT>=1.4.2']

setup(
    name='datapunt-authorization-django',
    version=version,
    description='Datapunt authorization check for Django',
    url='https://github.com/DatapuntAmsterdam/authorization_django',
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
