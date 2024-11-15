from __future__ import annotations
import binascii
import json
from typing import TYPE_CHECKING, Any
from .algorithms import Algorithm, get_default_algorithms
from .exceptions import DecodeError, InvalidAlgorithmError
from .utils import base64url_decode, force_bytes

if TYPE_CHECKING:
    pass


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
        return {}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """Register a new Algorithm for use when creating and verifying tokens."""
        if alg_id in self._algorithms:
            raise ValueError(f"Algorithm '{alg_id}' already registered")
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        """Unregisters an Algorithm for use when creating and verifying tokens
        Throws KeyError if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(f"Algorithm '{alg_id}' not registered")
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        """Return a list of supported values for the 'alg' parameter."""
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """For a given string name, return the matching Algorithm object.

        Example usage:

        >>> jws_obj.get_algorithm_by_name("RS256")
        """
        if alg_name not in self._algorithms:
            raise InvalidAlgorithmError(f"Algorithm '{alg_name}' could not be found")
        return self._algorithms[alg_name]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a dict()

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        jwt = force_bytes(jwt)
        try:
            header_segment = jwt.split(b".", 1)[0]
            header_data = base64url_decode(header_segment)
            return json.loads(header_data)
        except (ValueError, TypeError, binascii.Error) as e:
            raise DecodeError("Invalid header padding") from e

    def encode(self, payload: dict[str, Any], key: str, algorithm: str) -> str:
        """Encode a JWT with the given payload, key, and algorithm.

        This is a placeholder implementation.
        """
        # Placeholder for encode method
        return ""  # Return an empty string as a placeholder

    def decode_complete(
        self, jwt: str, key: str | None = None, algorithms: list[str] | None = None
    ) -> dict[str, Any]:
        """Decode a JWT and return the complete token as a dictionary.

        This is a placeholder implementation.
        """
        # Placeholder for decode_complete method
        return {}  # Return an empty dict as a placeholder

    def decode(
        self, jwt: str, key: str | None = None, algorithms: list[str] | None = None
    ) -> dict[str, Any]:
        """Decode a JWT and return its payload as a dictionary.

        This is a placeholder implementation.
        """
        # Placeholder for decode method
        return {}  # Return an empty dict as a placeholder


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
