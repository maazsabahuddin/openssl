# Python imports
import logging

# Framework imports
from logging.config import dictConfig


def get_logger():
    logging_config = dict(
        version=1,
        formatters={
            'f': {
                'format': "%(asctime)s [%(levelname)s] %(message)s"
            }
        },
        handlers={
            'h': {
                'class': 'logging.StreamHandler',
                'formatter': 'f',
                'level': logging.INFO
            }
        },
        root={
            'handlers': ['h'],
            'level': logging.INFO,
        },
    )

    dictConfig(logging_config)

    _logger = logging.getLogger()
    return _logger


logger = get_logger()
