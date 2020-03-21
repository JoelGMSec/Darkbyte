#!/usr/bin/env python3

import logging
import sys
import re
import os

# set logger
logger = logging.getLogger("Karma")

try:
    import requests

except ModuleNotFoundError as e:
    logger.error(e)
    logger.warn(
        "please install the requirements: $ sudo -H pip3 insall -r requirements.txt"
    )
    sys.exit(1)


class pwndb(object):

    """Docstring for pwndb. """

    def __init__(self, args):

        self.args = args
        self.site = "http://pwndb2am4tzkvold.onion/"
        self.data = {"luseropr": 1, "domainopr": 1, "submitform": "em"}

        proxy = self.args["--proxy"]
        if "//" in proxy:
            proxy = proxy.split("//")[1]

        self.session = requests.session()
        self.session.proxies = {
            "http": f"socks5h://{proxy}",
            "https": f"socks5h://{proxy}",
        }

    def get_request(self, data: dict) -> str:
        """ Get requests """

        try:
            req = self.session.post(self.site, data=data, timeout=(15, None))

        except requests.exceptions.ConnectTimeout as e:
            logger.error(e)
            logger.info(f"the site: {self.site} is down, try again later")
            sys.exit(1)

        except requests.exceptions.ConnectionError as e:
            logger.error(e)
            logger.info("please restart the tor service and try again")
            sys.exit(1)

        except Exception as e:
            logger.error(e)
            sys.exit(1)

        return req.text

    def response_parser(self, raw_resp: str) -> dict:
        """ Parse pwndb response """

        if not raw_resp:
            logger.warn("no results were obtained")
            sys.exit(1)

        logger.info("analyzing results:")
        resp = re.findall(r"\[(.*)", raw_resp)
        resp = [resp[n : n + 4] for n in range(0, len(resp), 4)]

        results = {}
        getinfo = lambda s: s.split("=>")[1].strip()
        for raw_email in resp:
            results[getinfo(raw_email[0])] = {
                "email": "{}@{}".format(getinfo(raw_email[1]), getinfo(raw_email[2])),
                "passw": getinfo(raw_email[3]),
            }

        return results

    def email_request(self, target: str, num_targets=1, i=1) -> str:
        """ Request with email """

        regex = r"(^[a-zA-Z0-9_.+%-]+@[a-zA-Z0-9-%]+\.[a-zA-Z0-9-%.]+$)"

        if re.match(regex, target):
            logger.info(f"{i}/{num_targets} request email: {target}")
            self.data["luser"] = target.split("@")[0]
            self.data["domain"] = target.split("@")[1]

            return self.get_request(self.data)

        else:
            logger.warn(f"invalid email: {target}")
            return None

    def search_localpart(self, target: str, num_targets=1, i=1) -> str:
        """ Request with localpart """

        regex = r"(^[a-zA-Z0-9_.+%-]+$)"

        if re.match(regex, target):
            logger.info(f"{i}/{num_targets} request local-part: {target}")
            self.data["luseropr"] = 1
            self.data["luser"] = target

            return self.get_request(self.data)

        else:
            logger.warn(f"invalid local-part: {target}")
            return None

    def search_domain(self, target: str, num_targets=1, i=1) -> str:
        """ Requests with domain """

        regex = r"(^[a-zA-Z0-9-%]+\.[a-zA-Z0-9-.%]+$)"

        if re.match(regex, target):
            logger.info(f"{i}/{num_targets} request domain: {target}")
            self.data["domainopr"] = 1
            self.data["domain"] = target
            return self.get_request(self.data)

        else:
            logger.warn("invalid domain: {}".format(target))
            return None

    def search_password(self, target, num_targets=1, i=1):
        """ Requests with password """

        logger.info(f"{i}/{num_targets} request password: {target}")
        self.data["submitform"] = "pw"
        self.data["password"] = target

        return self.get_request(self.data)

    def choose_function(self, target: str, num_targets=1, i=1):
        """
        Choose the corresponding function 
        according to the parameter
        """

        opts = {
            "--local-part": self.search_localpart,
            "--password": self.search_password,
            "--domain": self.search_domain,
        }

        for key, value in self.args.items():
            if value and key in opts:
                return opts[key](target, num_targets, i)

    def search_info(self) -> dict:
        """Start the information search"""

        opt_search = self.args["search"]
        opt_target = self.args["target"]
        target = self.args["<target>"]

        try:
            # if it's a file with multiple objectives
            if os.path.exists(target):
                targets = open(target, "r").readlines()
                num_targets = len(targets)

                response = ""
                for i, target in enumerate(targets, 1):
                    target = target.strip("\n")

                    if opt_search:
                        response += self.choose_function(target, num_targets, i)

                    if opt_target:
                        response += self.email_request(target, num_targets, i)

            elif opt_search:
                response = self.choose_function(target)

            elif opt_target and target:
                response = self.email_request(target)

        except KeyboardInterrupt:
            logger.warn("search has stopped")
            sys.exit(1)

        return self.response_parser(response)
