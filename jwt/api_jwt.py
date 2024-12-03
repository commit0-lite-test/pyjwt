from __future__ import annotations
import json
import warnings
from calendar import timegm
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional
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

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys


class PyJWT(api_jws.PyJWS):
    def __init__(self, options: Optional[dict[str, Any]] = None) -> None:
        super().__init__(options=options)

    def _get_default_options(self) -> dict[str, Any]:
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
        payload: dict[str, Any],
        key: str,
        algorithm: str = "HS256",
        headers: Optional[dict] = None,
        json_encoder: Optional[type[json.JSONEncoder]] = None,
    ) -> str:
        # Check that we have a mapping
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, got %s instead" % type(payload)
            )

        # Payload
        for time_claim in ["exp", "iat", "nbf"]:
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

        json_payload = json.dumps(
            payload, separators=(",", ":"), cls=json_encoder
        ).encode("utf-8")

        return super().encode(
            json_payload, key, algorithm, headers, json_encoder
        )

    def decode_complete(
        self,
        jwt: str,
        key: str | None = None,
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        merged_options = {**self.options, **(options or {})}
        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        decoded = super().decode_complete(jwt, key, algorithms, options, **kwargs)

        try:
            payload = json.loads(decoded["payload"])
        except ValueError as e:
            raise DecodeError("Invalid payload string: %s" % e)

        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")

        if verify_signature:
            self._validate_claims(payload, merged_options)

        decoded["payload"] = payload
        return decoded

    def decode(
        self,
        jwt: str,
        key: str | None = None,
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
        return decoded["payload"]

    def _validate_claims(
        self, payload: dict[str, Any], options: dict[str, Any]
    ) -> None:
        now = timegm(datetime.now(tz=timezone.utc).utctimetuple())

        if "verify_exp" in options and options["verify_exp"]:
            exp = payload.get("exp")
            if exp:
                try:
                    if int(exp) < now:
                        raise ExpiredSignatureError("Signature has expired")
                except ValueError:
                    raise DecodeError("Expiration Time claim (exp) must be an integer.")
            elif "exp" in options["require"]:
                raise MissingRequiredClaimError("Expiration Time claim (exp) is required")

        if "verify_nbf" in options and options["verify_nbf"]:
            nbf = payload.get("nbf")
            if nbf:
                try:
                    if int(nbf) > now:
                        raise ImmatureSignatureError("The token is not yet valid (nbf)")
                except ValueError:
                    raise DecodeError("Not Before claim (nbf) must be an integer.")
            elif "nbf" in options["require"]:
                raise MissingRequiredClaimError("Not Before claim (nbf) is required")

        if "verify_iat" in options and options["verify_iat"]:
            iat = payload.get("iat")
            if iat:
                try:
                    int(iat)
                except ValueError:
                    raise DecodeError("Issued At claim (iat) must be an integer.")
            elif "iat" in options["require"]:
                raise MissingRequiredClaimError("Issued At claim (iat) is required")

        if "verify_aud" in options and options["verify_aud"]:
            aud = payload.get("aud")
            if aud:
                if isinstance(aud, str):
                    aud = [aud]
                if not isinstance(aud, list):
                    raise InvalidAudienceError("Invalid audience")
            elif "aud" in options["require"]:
                raise MissingRequiredClaimError("Audience claim (aud) is required")

        if "verify_iss" in options and options["verify_iss"]:
            iss = payload.get("iss")
            if not iss and "iss" in options["require"]:
                raise MissingRequiredClaimError("Issuer claim (iss) is required")

        for claim in options["require"]:
            if claim not in payload:
                raise MissingRequiredClaimError(f"{claim} claim is required")


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
