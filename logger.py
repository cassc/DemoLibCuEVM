import logging
import os

log_level = os.getenv("PYCUEVM_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

log = logging.getLogger("pycuevm")
