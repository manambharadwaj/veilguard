"""VeilGuard — reduce credential exposure to AI coding assistants."""

from importlib.metadata import PackageNotFoundError, version

from veilguard.detect import detect_ai_tools, tool_display_name
from veilguard.initialize import init_project
from veilguard.scan import scan
from veilguard.secret_store import SecretStore
from veilguard.status import status
from veilguard.verify import verify

try:
    __version__ = version("veilguard")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = [
    "SecretStore",
    "__version__",
    "detect_ai_tools",
    "init_project",
    "scan",
    "status",
    "tool_display_name",
    "verify",
]
