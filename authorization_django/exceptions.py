class AuthorizationError(Exception):

    def __init__(
        self,
        status_code,
        code,
        msg,
        www_authenticate=None,
    ):
        self.status_code = status_code
        self.code = code
        self.message = msg
        self.www_authenticate = www_authenticate
        super().__init__(status_code, code, msg, www_authenticate)


class InsufficientScopeError(AuthorizationError):

    def __init__(
        self,
        status_code=401,
        code="insufficient_scope",
        msg="Unauthorized",
        www_authenticate='Bearer realm="datapunt", error="insufficient_scope"',
    ):
        super().__init__(status_code, code, msg, www_authenticate)


class ExpiredTokenError(AuthorizationError):

    def __init__(
        self,
        status_code=401,
        code="expired_token",
        msg="Unauthorized. Token expired.",
        www_authenticate='Bearer realm="datapunt", error="expired_token"',
    ):
        super().__init__(status_code, code, msg, www_authenticate)


class InvalidTokenError(AuthorizationError):

    def __init__(
        self,
        status_code=401,
        code="invalid_token",
        msg="Unauthorized. Invalid token.",
        www_authenticate='Bearer realm="datapunt", error="invalid_token"',
    ):
        super().__init__(status_code, code, msg, www_authenticate)


class InvalidRequestError(AuthorizationError):

    def __init__(
        self,
        status_code=400,
        code="invalid_request",
        msg="Invalid Authorization header format",
        www_authenticate='Bearer realm="datapunt", error="invalid_request", '
        'error_description="Invalid Authorization header format; '
        "should be: 'Bearer [token]'\"",
    ):
        super().__init__(status_code, code, msg, www_authenticate)
