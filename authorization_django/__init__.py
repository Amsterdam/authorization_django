"""
    authorization_django
    ~~~~~~~~~~~~~~~~~~~~

    Authorization middleware that uses JWTs for authentication.

    The following settings are used by the middleware, and can be configured in
    your ``settings.py`` in the ``DATAPUNT_AUTHZ`` dictionary.

    .. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

    ================================= =========================================
    ``JWT_SECRET_KEY``                (Required) Your JWT signing key
    ``JWT_ALGORITHM``                 (Required) Algorithm to use for the JWT
                                      message authentication code (MAC)
    ``LOGGER_NAME``                   Name of the logger. (Default =
                                      ``authorization_django``)
    ``LOGGER_LEVEL``                  Log level. Will be overwritten if running
                                      debug mode. (Default = ``INFO``)
    ``LOGGER_FORMAT``                 Log format
    ``LOGGER_FORMAT_DEBUG``           Log format for messages in debug mode
"""
from .middleware import authorization_middleware
import authorization_levels as levels

__all__ = (
    'authorization_middleware',
    'levels'
)
