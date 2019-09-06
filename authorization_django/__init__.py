"""
    authorization_django
    ~~~~~~~~~~~~~~~~~~~~

    Authorization middleware that uses JWTs for authentication.
"""
from .middleware import authorization_middleware

__all__ = (
    'authorization_middleware',
)
