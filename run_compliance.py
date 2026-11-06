"""Command-line entry point: python run_compliance.py

Exit codes: 0 = finished (or scan disabled), 1 = configuration error,
2 = Posit Connect authentication failure, 3 = other fatal error.
"""

from __future__ import annotations

import logging
import sys

from compliance.config import ConfigError
from compliance.connect_client import ConnectAuthError
from compliance.job import compliance_job, configure_logging


def main() -> int:
    configure_logging()
    log = logging.getLogger("branch_compliance")
    try:
        compliance_job()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 1
    except ConnectAuthError as exc:
        log.error("Posit Connect authentication failed: %s", exc)
        return 2
    except Exception:
        log.exception("Compliance scan aborted.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
