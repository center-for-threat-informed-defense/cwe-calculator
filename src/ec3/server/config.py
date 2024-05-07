"""Constants used to configure the server's logging.

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

from typing_extensions import Final

__LOGFILE_PFX: Final[str] = "%(asctime)s [%(name)s] %(levelname)s:"
LOGGING_FORMATTERS: Final[dict] = {
    "console_format": {
        "()": "uvicorn.logging.DefaultFormatter",
        "fmt": "%(levelprefix)s %(message)s",
        "use_colors": None,
    },
    "access_console_format": {
        "()": "uvicorn.logging.AccessFormatter",
        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
    },
    "logfile_format": {
        "format": __LOGFILE_PFX + "%(message)s",
        "datefmt": "%Y-%m-%d %H:%M:%S",
    },
    "access_logfile_format": {
        "()": "uvicorn.logging.AccessFormatter",
        "fmt": __LOGFILE_PFX + '%(client_addr)s - "%(request_line)s" %(status_code)s',
        "datefmt": "%Y-%m-%d %H:%M:%S",
        "use_colors": False,
    },
}
"""
The server's list of logging formatters.
"""


LOGGING_HANDLERS: Final[dict] = {
    "console_handler": {
        "formatter": "console_format",
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stdout",
    },
    "access_console_handler": {
        "formatter": "access_console_format",
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stdout",
    },
    "logfile_handler": {
        "formatter": "logfile_format",
        "class": "logging.FileHandler",
        "filename": "ec3.server.log",
    },
    "access_logfile_handler": {
        "formatter": "access_logfile_format",
        "class": "logging.FileHandler",
        "filename": "ec3.server.log",
    },
}
"""
The server's list of logging handlers.
"""


LOGGING_CONFIG: Final[dict] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": LOGGING_FORMATTERS,
    "handlers": LOGGING_HANDLERS,
    "loggers": {
        "": {
            "handlers": ["console_handler", "logfile_handler"],
            "level": "INFO",
        }
    },
}
"""
The server's root logging configuration.
"""


UVICORN_LOGGING_CONFIG: Final[dict] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": LOGGING_FORMATTERS,
    "handlers": LOGGING_HANDLERS,
    "loggers": {
        "uvicorn": {
            "handlers": ["console_handler", "logfile_handler"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {
            "handlers": ["access_console_handler", "access_logfile_handler"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
"""
The server's uvicorn logging configuration.
"""
