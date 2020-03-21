#!/usr/bin/env python3

import logging


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    FORMATS = {
        logging.WARNING: "\033[33m[!] %(msg)s \033[00m",
        logging.ERROR: "\033[31m[x] %(msg)s \033[00m",
        logging.DEBUG: "[-] %(msg)s",
        logging.INFO: "\033[32m[+] %(msg)s \033[00m",
        "DEFAULT": "%(msg)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
