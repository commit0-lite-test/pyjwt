from __future__ import annotations
import json
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache
import jwt

class PyJWKClient:

    def __init__(self, uri: str, cache_keys: bool=False, max_cached_keys: int=16, cache_jwk_set: bool=True, lifespan: int=300, headers: Optional[Dict[str, Any]]=None, timeout: int=30, ssl_context: Optional[SSLContext]=None):
        if headers is None:
            headers = {}
        self.uri = uri
        self.jwk_set_cache: Optional[JWKSetCache] = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cache_jwk_set:
            if lifespan <= 0:
                raise PyJWKClientError(f'Lifespan must be greater than 0, the input is "{lifespan}"')
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None
        if cache_keys:
            self.get_signing_key = lru_cache(maxsize=max_cached_keys)(self._get_signing_key)

    def get_jwk_set(self) -> PyJWKSet:
        if self.jwk_set_cache and self.jwk_set_cache.is_valid():
            return self.jwk_set_cache.jwk_set
        
        response = self._fetch_data()
        jwk_set = PyJWKSet.from_dict(json.loads(response.decode('utf-8')))
        
        if self.jwk_set_cache:
            self.jwk_set_cache.update(jwk_set)
        
        return jwk_set

    def get_signing_keys(self) -> List[PyJWK]:
        jwk_set = self.get_jwk_set()
        signing_keys = [key for key in jwk_set.keys if key.public_key_use in ('sig', None)]
        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")
        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        signing_keys = self.get_signing_keys()
        for key in signing_keys:
            if key.key_id == kid:
                return key
        raise PyJWKClientError(f"Unable to find a signing key that matches: {kid}")

    def get_signing_key_from_jwt(self, token: str) -> PyJWK:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        if not kid:
            raise PyJWKClientError("Unable to find a key identifier in the token header")
        return self.get_signing_key(kid)

    def _fetch_data(self) -> bytes:
        request = Request(self.uri, headers=self.headers)
        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                return response.read()
        except URLError as e:
            raise PyJWKClientConnectionError(f"Fail to fetch data from the url, err: {str(e)}")

    def _get_signing_key(self, kid: str) -> PyJWK:
        return self.get_signing_key(kid)
