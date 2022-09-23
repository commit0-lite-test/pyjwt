from __future__ import annotations

import json
import warnings
from calendar import timegm
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Type, Union

from . import api_jws
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    MissingRequiredClaimError,
)
from .warnings import RemovedInPyjwt3Warning


class PyJWT:
    def __init__(self, options=None):
        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    @staticmethod
    def _get_default_options() -> Dict[str, Union[bool, List[str]]]:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "require": [],
        }

    def encode(
        self,
        payload: Dict[str, Any],
        key: str,
        algorithm: Optional[str] = "HS256",
        headers: Optional[Dict[str, Any]] = None,
        json_encoder: Optional[Type[json.JSONEncoder]] = None,
    ) -> str:
        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError(
                "Expecting a mapping object, as JWT only supports "
                "JSON objects as payloads."
            )

        # Payload
        payload = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

        json_payload = json.dumps(
            payload, separators=(",", ":"), cls=json_encoder
        ).encode("utf-8")

        return api_jws.encode(json_payload, key, algorithm, headers, json_encoder)

    def decode_complete(
        self,
        jwt: str,
        key: str = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        # deprecated arg, remove in pyjwt3
        verify: Optional[bool] = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: Optional[bytes] = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[str] = None,
        leeway: Union[int, float, timedelta] = 0,
        # kwargs
        **kwargs,
    ) -> Dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        options = dict(options or {})  # shallow-copy or initialize an empty dict
        options.setdefault("verify_signature", True)

        # If the user has set the legacy `verify` argument, and it doesn't match
        # what the relevant `options` entry for the argument is, inform the user
        # that they're likely making a mistake.
        if verify is not None and verify != options["verify_signature"]:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
            )

        if not options["verify_signature"]:
            options.setdefault("verify_exp", False)
            options.setdefault("verify_nbf", False)
            options.setdefault("verify_iat", False)
            options.setdefault("verify_aud", False)
            options.setdefault("verify_iss", False)

        if options["verify_signature"] and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        decoded = api_jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=options,
            detached_payload=detached_payload,
        )

        try:
            payload = json.loads(decoded["payload"])
        except ValueError as e:
            raise DecodeError(f"Invalid payload string: {e}")
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")

        merged_options = {**self.options, **options}
        self._validate_claims(
            payload, merged_options, audience=audience, issuer=issuer, leeway=leeway
        )

        decoded["payload"] = payload
        return decoded

    def decode(
        self,
        jwt: str,
        key: str = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        # deprecated arg, remove in pyjwt3
        verify: Optional[bool] = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: Optional[bytes] = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: Optional[Union[str, Iterable[str]]] = None,
        issuer: Optional[str] = None,
        leeway: Union[int, float, timedelta] = 0,
        # kwargs
        **kwargs,
    ) -> Dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
        )
        return decoded["payload"]

    def _validate_claims(self, payload, options, audience=None, issuer=None, leeway=0):
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if audience is not None and not isinstance(audience, (str, Iterable)):
            raise TypeError("audience must be a string, iterable or None")

        self._validate_required_claims(payload, options)

        now = timegm(datetime.now(tz=timezone.utc).utctimetuple())

        if "iat" in payload and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)

        if "nbf" in payload and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)

        if "exp" in payload and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)

        if options["verify_aud"]:
            self._validate_aud(payload, audience)

    def _validate_required_claims(self, payload, options):
        for claim in options["require"]:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    def _validate_iat(self, payload, now, leeway):
        try:
            int(payload["iat"])
        except ValueError:
            raise InvalidIssuedAtError("Issued At claim (iat) must be an integer.")

    def _validate_nbf(self, payload, now, leeway):
        try:
            nbf = int(payload["nbf"])
        except ValueError:
            raise DecodeError("Not Before claim (nbf) must be an integer.")

        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(self, payload, now, leeway):
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an" " integer.")

        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(self, payload, audience):
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, str):
            audience = [audience]

        if all(aud not in audience_claims for aud in audience):
            raise InvalidAudienceError("Invalid audience")

    def _validate_iss(self, payload, issuer):
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != issuer:
            raise InvalidIssuerError("Invalid issuer")


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
