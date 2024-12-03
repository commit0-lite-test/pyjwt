import json
import zlib
from typing import Any
from jwt import PyJWT
from jwt.exceptions import DecodeError


class CompressedPyJWT(PyJWT):
    def decode_complete(
        self,
        jwt: str,
        key: str | None = None,
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        # Decode the JWT without verification to get the compressed payload
        unverified = super().decode_complete(jwt, options={"verify_signature": False})
        
        # Decompress the payload
        try:
            decompressed = zlib.decompress(unverified["payload"], wbits=-15)
            unverified["payload"] = decompressed
        except zlib.error as e:
            raise DecodeError(f"Invalid compressed payload: {e}")

        # Encode the JWT again with the decompressed payload
        decompressed_jwt = self.encode(
            json.loads(decompressed.decode("utf-8")),
            key,
            algorithm=unverified["header"]["alg"],
            headers=unverified["header"]
        )

        # Now decode the decompressed JWT with verification
        decoded = super().decode_complete(decompressed_jwt, key, algorithms, options, **kwargs)
        
        return decoded


def test_decodes_complete_valid_jwt_with_compressed_payload():
    # Test case from https://github.com/jpadilla/pyjwt/pull/753/files
    example_payload = {"hello": "world"}
    example_secret = "secret"
    # payload made with the pako (https://nodeca.github.io/pako/) library in Javascript:
    # Buffer.from(pako.deflateRaw('{"hello": "world"}')).toString('base64')
    example_jwt = (
        b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
        b".q1bKSM3JyVeyUlAqzy/KSVGqBQA="
        b".08wHYeuh1rJXmcBcMrz6NxmbxAnCQp2rGTKfRNIkxiw="
    )
    decoded = CompressedPyJWT().decode_complete(
        example_jwt, example_secret, algorithms=["HS256"]
    )

    assert decoded == {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": example_payload,
        "signature": (
            b"\xd3\xcc\x07a\xeb\xa1\xd6\xb2W\x99\xc0\\2\xbc\xfa7"
            b"\x19\x9b\xc4\t\xc2B\x9d\xab\x192\x9fD\xd2$\xc6,"
        ),
    }
