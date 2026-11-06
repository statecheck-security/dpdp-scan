"""dpdp-scan: find Indian personal data in code, schemas, fixtures and logs.

Every finding names the DPDP Act, 2023 section or DPDP Rules, 2025 rule it
touches. The tool reports an inventory and risky patterns; it never gives a
compliance verdict, and it is not legal advice.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("dpdp-scan")
except PackageNotFoundError:  # running from a checkout without an install
    __version__ = "0.0.0"

__all__ = ["__version__"]
