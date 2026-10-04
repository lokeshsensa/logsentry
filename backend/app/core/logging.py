import logging
import sys

def setup_logging():
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    # Suppress overly verbose loggers if needed
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    return logging.getLogger("logsentry")

logger = setup_logging()
