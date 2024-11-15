class PyJWTError(Exception):
    """Base class for all exceptions"""

    def __init__(self, message: str = "An error occurred with PyJWT") -> None:
        self.message = message
        super().__init__(self.message)


class InvalidTokenError(PyJWTError):
    def __init__(self, message: str = "Invalid token") -> None:
        super().__init__(message)


class DecodeError(InvalidTokenError):
    def __init__(self, message: str = "Token could not be decoded") -> None:
        super().__init__(message)


class InvalidSignatureError(DecodeError):
    def __init__(self, message: str = "Signature verification failed") -> None:
        super().__init__(message)


class ExpiredSignatureError(InvalidTokenError):
    def __init__(self, message: str = "Signature has expired") -> None:
        super().__init__(message)


class InvalidAudienceError(InvalidTokenError):
    def __init__(self, message: str = "Invalid audience") -> None:
        super().__init__(message)


class InvalidIssuerError(InvalidTokenError):
    def __init__(self, message: str = "Invalid issuer") -> None:
        super().__init__(message)


class InvalidIssuedAtError(InvalidTokenError):
    def __init__(self, message: str = "Invalid issued at time") -> None:
        super().__init__(message)


class ImmatureSignatureError(InvalidTokenError):
    def __init__(self, message: str = "The token is not yet valid (nbf)") -> None:
        super().__init__(message)


class InvalidKeyError(PyJWTError):
    def __init__(self, message: str = "Invalid key") -> None:
        super().__init__(message)


class InvalidAlgorithmError(InvalidTokenError):
    def __init__(self, message: str = "Invalid algorithm") -> None:
        super().__init__(message)


class MissingRequiredClaimError(InvalidTokenError):
    def __init__(self, claim: str) -> None:
        self.claim = claim
        super().__init__(f'Token is missing the "{self.claim}" claim')

    def __str__(self) -> str:
        return f'Token is missing the "{self.claim}" claim'


class PyJWKError(PyJWTError):
    def __init__(self, message: str = "An error occurred with JWK") -> None:
        super().__init__(message)


class PyJWKSetError(PyJWTError):
    def __init__(self, message: str = "An error occurred with JWK Set") -> None:
        super().__init__(message)


class PyJWKClientError(PyJWTError):
    def __init__(self, message: str = "An error occurred with JWK Client") -> None:
        super().__init__(message)


class PyJWKClientConnectionError(PyJWKClientError):
    def __init__(
        self, message: str = "Connection error occurred with JWK Client"
    ) -> None:
        super().__init__(message)
