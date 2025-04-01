from drf_spectacular.extensions import OpenApiAuthenticationExtension


class JWTTokenScheme(OpenApiAuthenticationExtension):
    target_class = "authorization_django.extensions.scheme.JWTAuthentication"
    name = "JWTAuthentication"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
        }
