from __future__ import annotations
import hashlib
import hmac
import json
import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, Union, cast, overload
from .exceptions import InvalidKeyError
from .types import HashlibHash, JWKDict
from .utils import base64url_decode, base64url_encode, der_to_raw_signature, force_bytes, from_base64url_uint, is_pem_format, is_ssh_key, raw_to_der_signature, to_base64url_uint
if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256K1, SECP256R1, SECP384R1, SECP521R1, EllipticCurve, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers, EllipticCurvePublicKey, EllipticCurvePublicNumbers
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateNumbers, RSAPublicKey, RSAPublicNumbers, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp, rsa_recover_prime_factors
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key, load_pem_public_key, load_ssh_public_key
    has_crypto = True
except ModuleNotFoundError:
    has_crypto = False
if TYPE_CHECKING:
    AllowedRSAKeys = RSAPrivateKey | RSAPublicKey
    AllowedECKeys = EllipticCurvePrivateKey | EllipticCurvePublicKey
    AllowedOKPKeys = Ed25519PrivateKey | Ed25519PublicKey | Ed448PrivateKey | Ed448PublicKey
    AllowedKeys = AllowedRSAKeys | AllowedECKeys | AllowedOKPKeys
    AllowedPrivateKeys = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey
    AllowedPublicKeys = RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey | Ed448PublicKey
requires_cryptography = {'RS256', 'RS384', 'RS512', 'ES256', 'ES256K', 'ES384', 'ES521', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA'}

def get_default_algorithms() -> dict[str, Algorithm]:
    """
    Returns the algorithms that are implemented by the library.
    """
    default_algorithms = {
        'none': NoneAlgorithm(),
        'HS256': HMACAlgorithm(HMACAlgorithm.SHA256),
        'HS384': HMACAlgorithm(HMACAlgorithm.SHA384),
        'HS512': HMACAlgorithm(HMACAlgorithm.SHA512),
    }
    
    if has_crypto:
        default_algorithms.update({
            'RS256': RSAAlgorithm(RSAAlgorithm.SHA256),
            'RS384': RSAAlgorithm(RSAAlgorithm.SHA384),
            'RS512': RSAAlgorithm(RSAAlgorithm.SHA512),
            'ES256': ECAlgorithm(ECAlgorithm.SHA256),
            'ES384': ECAlgorithm(ECAlgorithm.SHA384),
            'ES512': ECAlgorithm(ECAlgorithm.SHA512),
            'PS256': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
            'PS384': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
            'PS512': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
            'EdDSA': OKPAlgorithm(),
        })
    
    return default_algorithms

class Algorithm(ABC):
    """
    The interface for an algorithm used to sign and verify tokens.
    """

    def compute_hash_digest(self, bytestr: bytes) -> bytes:
        """
        Compute a hash digest using the specified algorithm's hash algorithm.

        If there is no hash algorithm, raises a NotImplementedError.
        """
        if hasattr(self, 'hash_alg'):
            return self.hash_alg(bytestr).digest()
        raise NotImplementedError("Hash algorithm not specified")

    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """
        pass

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        pass

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """
        pass

    @staticmethod
    @abstractmethod
    def to_jwk(key_obj, as_dict: bool=False) -> Union[JWKDict, str]:
        """
        Serializes a given key into a JWK
        """
        pass

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        """
        Deserializes a given key from JWK back into a key object
        """
        pass

class NoneAlgorithm(Algorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prepare_key(self, key: Any) -> None:
        return None

    def sign(self, msg: bytes, key: Any) -> bytes:
        return b''

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        return False

    @staticmethod
    def to_jwk(key_obj, as_dict: bool = False) -> Union[JWKDict, str]:
        if as_dict:
            return {"kty": "none"}
        return json.dumps({"kty": "none"})

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> None:
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        if not isinstance(jwk, dict) or jwk.get('kty') != 'none':
            raise InvalidKeyError('Not a valid "none" key')
        return None

class HMACAlgorithm(Algorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256: ClassVar[HashlibHash] = hashlib.sha256
    SHA384: ClassVar[HashlibHash] = hashlib.sha384
    SHA512: ClassVar[HashlibHash] = hashlib.sha512

    def __init__(self, hash_alg: HashlibHash) -> None:
        self.hash_alg = hash_alg

    def prepare_key(self, key: Any) -> bytes:
        key = force_bytes(key)
        return key

    def sign(self, msg: bytes, key: Any) -> bytes:
        key = self.prepare_key(key)
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        key = self.prepare_key(key)
        return hmac.compare_digest(sig, self.sign(msg, key))

    @staticmethod
    def to_jwk(key_obj: bytes, as_dict: bool = False) -> Union[JWKDict, str]:
        jwk = {
            'kty': 'oct',
            'k': base64url_encode(force_bytes(key_obj)).decode('ascii')
        }
        if as_dict:
            return jwk
        return json.dumps(jwk)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        if not isinstance(jwk, dict) or jwk.get('kty') != 'oct':
            raise InvalidKeyError('Not a valid HMAC key')
        k = jwk.get('k')
        if not k:
            raise InvalidKeyError('k is required for HMAC keys')
        return base64url_decode(k)
if has_crypto:

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """
        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
            self.hash_alg = hash_alg

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """
        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
            self.hash_alg = hash_alg

    class RSAPSSAlgorithm(RSAAlgorithm):
        """
        Performs a signature using RSASSA-PSS with MGF1
        """

    class OKPAlgorithm(Algorithm):
        """
        Performs signing and verification operations using EdDSA

        This class requires ``cryptography>=2.6`` to be installed.
        """

        def __init__(self, **kwargs: Any) -> None:
            pass

        def sign(self, msg: str | bytes, key: Ed25519PrivateKey | Ed448PrivateKey) -> bytes:
            """
            Sign a message ``msg`` using the EdDSA private key ``key``
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey}Ed448PrivateKey key: A :class:`.Ed25519PrivateKey`
                or :class:`.Ed448PrivateKey` isinstance
            :return bytes signature: The signature, as bytes
            """
            pass

        def verify(self, msg: str | bytes, key: AllowedOKPKeys, sig: str | bytes) -> bool:
            """
            Verify a given ``msg`` against a signature ``sig`` using the EdDSA key ``key``

            :param str|bytes sig: EdDSA signature to check ``msg`` against
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey|Ed25519PublicKey|Ed448PrivateKey|Ed448PublicKey key:
                A private or public EdDSA key instance
            :return bool verified: True if signature is valid, False if not.
            """
            pass
