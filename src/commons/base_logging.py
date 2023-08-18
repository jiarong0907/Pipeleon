import enum
import os
import colorlog
import logging


class LogLevel(enum.Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"


default_log_colors = {
    "DEBUG": "cyan",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold_red",
}

handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s %(levelname)s %(filename)s:%(lineno)d: %(message)s", log_colors=default_log_colors
    )
)
logger = colorlog.getLogger("main")
logger.addHandler(handler)
logger.setLevel("DEBUG")

log_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tmp.log")
file_handler = logging.FileHandler(log_path, mode="w")
file_formmter = logging.Formatter("%(asctime)s %(levelname)s %(filename)s:%(lineno)d: %(message)s")
file_handler.setFormatter(file_formmter)
logger.addHandler(file_handler)


def set_log_level(level: LogLevel):
    logger.setLevel(level.value)
