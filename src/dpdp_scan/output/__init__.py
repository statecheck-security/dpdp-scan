"""Report writers: SARIF 2.1.0, JSON inventory, Markdown summary, text."""

from dpdp_scan.output.inventory import build_inventory
from dpdp_scan.output.markdown import build_markdown
from dpdp_scan.output.sarif import build_sarif

__all__ = ["build_inventory", "build_markdown", "build_sarif"]
