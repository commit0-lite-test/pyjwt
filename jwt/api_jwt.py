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

        # Extract JWT-specific kwargs
        audience = kwargs.pop('audience', None)
        issuer = kwargs.pop('issuer', None)
        leeway = kwargs.pop('leeway', None)

        # Update options with JWT-specific parameters
        if audience is not None:
            merged_options['audience'] = audience
        if issuer is not None:
            merged_options['issuer'] = issuer
        if leeway is not None:
            merged_options['leeway'] = leeway

        for kwarg in kwargs:
            warnings.warn(
                f"The '{kwarg}' argument is not supported and will be ignored.",
                category=RemovedInPyjwt3Warning,
                stacklevel=2
            )

        decoded = super().decode_complete(jwt, key, algorithms, merged_options)

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
        leeway = options.get('leeway', 0)
        if isinstance(leeway, timedelta):
            leeway = int(leeway.total_seconds())

        if "verify_exp" in options and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if "verify_iat" in options and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)

        if "verify_nbf" in options and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)

        if "verify_aud" in options and options["verify_aud"]:
            self._validate_aud(payload, options)

        if "verify_iss" in options and options["verify_iss"]:
            self._validate_iss(payload, options)

        self._validate_required_claims(payload, options)

    def _validate_required_claims(self, payload, options):
        for claim in options.get("require", []):
            if claim not in payload:
                raise MissingRequiredClaimError(f"{claim} claim is required")

    def _validate_exp(self, payload, now, leeway):
        try:
            exp = int(payload['exp'])
        except KeyError:
            pass
        except ValueError:
            raise DecodeError('Expiration Time claim (exp) must be an integer.')
        else:
            if exp < (now - leeway):
                raise ExpiredSignatureError('Signature has expired')

    def _validate_iat(self, payload, now, leeway):
        try:
            int(payload['iat'])
        except KeyError:
            pass
        except ValueError:
            raise DecodeError('Issued At claim (iat) must be an integer.')
        else:
            if payload['iat'] > (now + leeway):
                raise InvalidIssuedAtError('Issued At claim (iat) cannot be in the future')

    def _validate_nbf(self, payload, now, leeway):
        try:
            nbf = int(payload['nbf'])
        except KeyError:
            pass
        except ValueError:
            raise DecodeError('Not Before claim (nbf) must be an integer.')
        else:
            if nbf > (now + leeway):
                raise ImmatureSignatureError('The token is not yet valid (nbf)')

    def _validate_aud(self, payload, options):
        if 'aud' not in payload:
            # if aud is required but not present, it will be caught in _validate_required_claims
            return

        audience = options.get('audience')
        payload_aud = payload['aud']

        if audience is None:
            return

        if isinstance(payload_aud, str):
            payload_aud = [payload_aud]
        if isinstance(audience, str):
            audience = [audience]

        if not isinstance(payload_aud, list):
            raise InvalidAudienceError('Invalid claim format in token')
        if not any(aud in payload_aud for aud in audience):
            raise InvalidAudienceError('Invalid audience')

    def _validate_iss(self, payload, options):
        if 'iss' not in payload:
            # if iss is required but not present, it will be caught in _validate_required_claims
            return

        issuer = options.get('issuer')
        if issuer is not None:
            if payload['iss'] != issuer:
                raise InvalidIssuerError('Invalid issuer')


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
