from __future__ import annotations
import json
import time
from typing import Any
from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import InvalidKeyError, PyJWKError, PyJWKSetError, PyJWTError
from .types import JWKDict

class PyJWK:

    def __init__(self, jwk_data: JWKDict, algorithm: str | None=None) -> None:
        self._algorithms = get_default_algorithms()
        self._jwk_data = jwk_data
        self.key_type = self._jwk_data.get('kty', None)
        if not self.key_type:
            raise InvalidKeyError(f'kty is not found: {self._jwk_data}')
        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get('alg', None)
        if not algorithm:
            crv = self._jwk_data.get('crv', None)
            if self.key_type == 'EC':
                if crv == 'P-256' or not crv:
                    algorithm = 'ES256'
                elif crv == 'P-384':
                    algorithm = 'ES384'
                elif crv == 'P-521':
                    algorithm = 'ES512'
                elif crv == 'secp256k1':
                    algorithm = 'ES256K'
                else:
                    raise InvalidKeyError(f'Unsupported crv: {crv}')
            elif self.key_type == 'RSA':
                algorithm = 'RS256'
            elif self.key_type == 'oct':
                algorithm = 'HS256'
            elif self.key_type == 'OKP':
                if not crv:
                    raise InvalidKeyError(f'crv is not found: {self._jwk_data}')
                if crv == 'Ed25519':
                    algorithm = 'EdDSA'
                else:
                    raise InvalidKeyError(f'Unsupported crv: {crv}')
            else:
                raise InvalidKeyError(f'Unsupported kty: {self.key_type}')
        if not has_crypto and algorithm in requires_cryptography:
            raise PyJWKError(f"{algorithm} requires 'cryptography' to be installed.")
        self.Algorithm = self._algorithms.get(algorithm)
        if not self.Algorithm:
            raise PyJWKError(f'Unable to find an algorithm for key: {self._jwk_data}')
        self.key = self.Algorithm.from_jwk(self._jwk_data)
        self.key_id = self._jwk_data.get('kid')
        self.public_key_use = self._jwk_data.get('use')

    @classmethod
    def from_dict(cls, jwk_dict: JWKDict, algorithm: str | None = None) -> 'PyJWK':
        return cls(jwk_dict, algorithm)

    @classmethod
    def from_json(cls, jwk_json: str, algorithm: str | None = None) -> 'PyJWK':
        try:
            jwk_dict = json.loads(jwk_json)
        except ValueError as e:
            raise PyJWKError("Invalid JSON string") from e
        return cls.from_dict(jwk_dict, algorithm)

class PyJWKSet:

    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys = []
        if not keys:
            raise PyJWKSetError('The JWK Set did not contain any keys')
        if not isinstance(keys, list):
            raise PyJWKSetError('Invalid JWK Set value')
        for key in keys:
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError:
                continue
        if len(self.keys) == 0:
            raise PyJWKSetError("The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?")

    def __getitem__(self, kid: str) -> 'PyJWK':
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f'keyset has no key for kid: {kid}')

    @classmethod
    def from_dict(cls, jwk_set_dict: dict) -> 'PyJWKSet':
        if not isinstance(jwk_set_dict, dict) or 'keys' not in jwk_set_dict:
            raise PyJWKSetError('Invalid JWK Set format')
        return cls(jwk_set_dict['keys'])

    @classmethod
    def from_json(cls, jwk_set_json: str) -> 'PyJWKSet':
        try:
            jwk_set_dict = json.loads(jwk_set_json)
        except ValueError as e:
            raise PyJWKSetError("Invalid JSON string") from e
        return cls.from_dict(jwk_set_dict)

class PyJWTSetWithTimestamp:

    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()
