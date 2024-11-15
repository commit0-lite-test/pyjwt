import json
import platform
import sys
from typing import Dict, Any
from . import __version__ as pyjwt_version

try:
    import cryptography

    cryptography_version = cryptography.__version__
except ImportError:
    cryptography_version = "Not installed (ImportError)"


def info() -> Dict[str, Dict[str, Any]]:
    """Generate information for a bug report.
    Based on the requests package help utility module.
    """
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
        },
        "dependencies": {
            "pyjwt": pyjwt_version,
            "cryptography": cryptography_version,
        },
        "system": {
            "python": sys.version,
            "executable": sys.executable,
        },
    }


def main() -> None:
    """Pretty-print the bug information as JSON."""
    print(json.dumps(info(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
