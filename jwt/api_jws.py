from __future__ import annotations
import binascii
import json
from typing import TYPE_CHECKING, Any
from .algorithms import Algorithm, get_default_algorithms
from .exceptions import DecodeError, InvalidAlgorithmError, InvalidTokenError
from .utils import base64url_decode, base64url_encode, force_bytes

if TYPE_CHECKING:
    from typing import Optional


class PyJWS:
    header_typ = "JWT"

    def __init__(
        self, algorithms: list[str] | None = None, options: dict[str, Any] | None = None
    ) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms) if algorithms is not None else set(self._algorithms)
        )
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]
        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    def _get_default_options(self) -> dict[str, Any]:
        return {"verify_signature": True}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        if alg_id in self._algorithms:
            raise ValueError(f"Algorithm '{alg_id}' already registered")
        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        if alg_id not in self._algorithms:
            raise KeyError(f"Algorithm '{alg_id}' not registered")
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        if alg_name not in self._algorithms:
            raise InvalidAlgorithmError(f"Algorithm '{alg_name}' could not be found")
        return self._algorithms[alg_name]

    def encode(
        self,
        payload: bytes | str,
        key: str,
        algorithm: str = "HS256",
        headers: Optional[dict] = None,
        json_encoder: Optional[type[json.JSONEncoder]] = None,
    ) -> str:
        if algorithm not in self._valid_algs:
            raise NotImplementedError("Algorithm not supported")

        if not isinstance(headers, dict):
            headers = {}

        header = {"typ": self.header_typ, "alg": algorithm}
        header.update(headers)

        json_header = json.dumps(
            header,
            separators=(",", ":"),
            cls=json_encoder,
        ).encode("utf-8")

        segments = [
            base64url_encode(json_header),
            base64url_encode(payload),
        ]

        signing_input = b".".join(segments)
        try:
            alg_obj = self._algorithms[algorithm]
            key = alg_obj.prepare_key(key)
            signature = alg_obj.sign(signing_input, key)
        except Exception as e:
            raise TypeError("Unable to encode JWT") from e

        segments.append(base64url_encode(signature))

        return b".".join(segments).decode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: str | None = None,
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        options = {**self.options, **(options or {})}
        verify_signature = options["verify_signature"]

        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        try:
            header_segment, payload_segment, crypto_segment = jwt.split(b".", 2)
        except ValueError:
            raise DecodeError("Not enough segments")

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise DecodeError("Invalid header padding")

        try:
            header = json.loads(header_data)
        except ValueError as e:
            raise DecodeError("Invalid header string: %s" % e)

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        try:
            payload = base64url_decode(payload_segment)
        except (TypeError, binascii.Error):
            raise DecodeError("Invalid payload padding")

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error):
            raise DecodeError("Invalid crypto padding")

        if verify_signature:
            if algorithms is None:
                raise DecodeError(
                    "It is required that you pass in a value for the "
                    '"algorithms" argument when calling decode().'
                )

            try:
                alg = header["alg"]
            except KeyError:
                raise DecodeError("Unable to find the algorithm to decode the JWT")

            if alg not in algorithms:
                raise InvalidAlgorithmError("The specified alg value is not allowed")

            try:
                alg_obj = self._algorithms[alg]
                key = alg_obj.prepare_key(key)

                if not alg_obj.verify(
                    b".".join([header_segment, payload_segment]), key, signature
                ):
                    raise DecodeError("Signature verification failed")
            except KeyError:
                raise InvalidAlgorithmError("Algorithm not supported")

        return {
            "header": header,
            "payload": payload,
            "signature": signature,
        }

    def decode(
        self,
        jwt: str | bytes,
        key: str | None = None,
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> Any:
        decoded = self.decode_complete(jwt, key, algorithms, options)
        return decoded["payload"]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns the decoded headers without verification of any kind."""
        jwt = force_bytes(jwt)
        try:
            header_segment = jwt.split(b".", 1)[0]
        except ValueError:
            raise InvalidTokenError("Wrong number of segments in token")

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise InvalidTokenError("Invalid header padding")

        try:
            header = json.loads(header_data)
        except ValueError:
            raise InvalidTokenError("Invalid header string")

        if not isinstance(header, dict):
            raise InvalidTokenError("Invalid header string: must be a json object")

        return header


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
