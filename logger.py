import logging
from datetime import datetime
from pathlib import Path

def setup_logger(logdir="logs"):
    """
    Set up a logger that writes to both console and a timestamped log file.
    Returns:
        logger (logging.Logger): Configured logger instance.
        log_path (Path): Path to the created log file.
    """
    logdir = Path(logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    log_path = logdir / f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"

    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    # Console output handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("%(levelname)s | %(message)s")
    console_handler.setFormatter(console_format)
    logging.getLogger().addHandler(console_handler)

    return logging.getLogger(__name__), log_path
