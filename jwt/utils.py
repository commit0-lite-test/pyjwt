import base64
import re
from typing import Union

try:
    import cryptography  # type: ignore # noqa: F401
except ImportError:
    cryptography = None
_PEMS = {
    b"CERTIFICATE",
    b"TRUSTED CERTIFICATE",
    b"PRIVATE KEY",
    b"PUBLIC KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"RSA PUBLIC KEY",
    b"EC PRIVATE KEY",
    b"DH PARAMETERS",
    b"NEW CERTIFICATE REQUEST",
    b"CERTIFICATE REQUEST",
    b"SSH2 PUBLIC KEY",
    b"SSH2 ENCRYPTED PRIVATE KEY",
    b"X509 CRL",
}
_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEMS)
    + b")[- ]----\r?\n.+?\r?\n----[- ]END \\1[- ]----\r?\n?",
    re.DOTALL,
)
_CERT_SUFFIX = b"-cert-v01@openssh.com"
_SSH_PUBKEY_RC = re.compile(b"\\A(\\S+)[ \\t]+(\\S+)")
_SSH_KEY_FORMATS = [
    b"ssh-ed25519",
    b"ssh-rsa",
    b"ssh-dss",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
]


def force_bytes(value: Union[str, bytes]) -> bytes:
    """Convert the input to bytes.

    Args:
    ----
        value (Union[str, bytes]): The input value to convert.

    Returns:
    -------
        bytes: The input converted to bytes.

    Raises:
    ------
        TypeError: If the input is not str or bytes.

    """
    if isinstance(value, str):
        return value.encode("utf-8")
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError("Expected str or bytes, got %s" % type(value))


def force_unicode(value: Union[str, bytes]) -> str:
    """Convert the input to a unicode string.

    Args:
    ----
        value (Union[str, bytes]): The input value to convert.

    Returns:
    -------
        str: The input converted to a unicode string.

    Raises:
    ------
        TypeError: If the input is not str or bytes.

    """
    if isinstance(value, bytes):
        return value.decode("utf-8")
    elif isinstance(value, str):
        return value
    else:
        raise TypeError("Expected str or bytes, got %s" % type(value))


def base64url_encode(input: bytes) -> bytes:
    """Encode the input using base64url encoding.

    Args:
    ----
        input (bytes): The input to encode.

    Returns:
    -------
        bytes: The base64url encoded input.

    """
    return base64.urlsafe_b64encode(input).rstrip(b"=")


def base64url_decode(input: Union[str, bytes]) -> bytes:
    """Decode the input from base64url encoding.

    Args:
    ----
        input (Union[str, bytes]): The input to decode.

    Returns:
    -------
        bytes: The decoded input.

    """
    input = force_bytes(input)
    padded = input + b"=" * (4 - len(input) % 4)
    return base64.urlsafe_b64decode(padded)


def to_base64url_uint(val: int) -> bytes:
    """Convert an integer to a base64url-encoded string.

    Args:
    ----
        val (int): The integer to convert.

    Returns:
    -------
        bytes: The base64url-encoded representation of the integer.

    Raises:
    ------
        ValueError: If the input is negative.

    """
    if val < 0:
        raise ValueError("Must be a positive integer")
    int_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64url_encode(int_bytes)


def from_base64url_uint(val: Union[str, bytes]) -> int:
    """Convert a base64url-encoded string to an integer.

    Args:
    ----
        val (Union[str, bytes]): The base64url-encoded string to convert.

    Returns:
    -------
        int: The integer representation of the input.

    """
    int_bytes = base64url_decode(val)
    return int.from_bytes(int_bytes, byteorder="big")


def merge_dict(original: dict, updates: dict) -> dict:
    """Merge two dictionaries recursively.

    Args:
    ----
        original (dict): The original dictionary.
        updates (dict): The dictionary with updates to merge.

    Returns:
    -------
        dict: A new dictionary with the merged contents.

    """
    if not updates:
        return original

    merged = original.copy()
    for key, value in updates.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key] = merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged
