import multiprocessing
import os
import re
import sys

from engines.engine import Engines

# external modules
from subbrute import subbrute

from util.port_scanner import PortScanner
from util.util import Util

# Python 2.x and 3.x compatibility
if sys.version >= '3':
    import urllib.parse as urlparse
else:
    import urlparse

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

class SubScann3r:
    def __init__(self, domain, logger, scan_flags):
        self.logger = logger
        self.domain = domain
        self.scan_flags = scan_flags

    def scan(self):
        bruteforce_list = set()
        search_list = set()

        if is_windows:
            subdomains_queue = list()
        else:
            subdomains_queue = multiprocessing.Manager().list()

        # Check Bruteforce Status
        # if self.scan_flags.BruteForce or self.scan_flags.BruteForce is None:
        #     self.scan_flags.BruteForce = True

        # Check Takeover Status
        # if self.scan_flags.TakeoverCheck or self.scan_flags.TakeoverCheck is None:
        #     self.scan_flags.TakeoverCheck = True

        # Validate domain
        domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
        if not domain_check.match(self.domain):
            if not self.scan_flags.Silent:
                print(self.logger.R + "Error: Please enter a valid domain" + self.logger.W)
            return []

        if not self.domain.startswith('http://') or not self.domain.startswith('https://'):
            self.domain = 'http://' + self.domain

        parsed_domain = urlparse.urlparse(self.domain)

        if not self.scan_flags.Silent:
            print(self.logger.B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + self.logger.W)

        if self.scan_flags.Verbose and not self.scan_flags.Silent:
            print(self.logger.Y + "[-] verbosity is enabled, will show the subdomains results in realtime" + self.logger.W)



        chosenEnums = []

        if self.scan_flags.Engines is None:
            chosenEnums = Engines.supported_engines.values()
        else:
            engines = self.scan_flags.Engines.split(',')
            for engine in engines:
                if engine.lower() in Engines.supported_engines:
                    chosenEnums.append(Engines.supported_engines[engine.lower()])

        # Start the engines enumeration
        enums = [enum(self.domain, [], q=subdomains_queue, silent=self.scan_flags.Silent, logger=self.logger) for enum in chosenEnums]
        for enum in enums:
            enum.start()
        for enum in enums:
            enum.join()

        subdomains = set(subdomains_queue)
        for subdomain in subdomains:
            search_list.add(subdomain)

        if self.scan_flags.BruteForce:
            if not self.scan_flags.Silent:
                print(self.logger.G + "[-] Starting bruteforce module now using subbrute.." + self.logger.W)
            record_type = False
            path_to_file = os.path.dirname(os.path.realpath(__file__))
            subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
            resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
            process_count = self.scan_flags.ThreadCount
            output = False
            json_output = False
            bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count,
                                                    output, json_output, search_list, self.scan_flags.Verbose)

        subdomains = search_list.union(bruteforce_list)

        if subdomains:
            subdomains = sorted(subdomains, key=Util.subdomain_sorting_key)

            if self.scan_flags.SaveFile:
                Util.write_file(self.scan_flags.SaveFile, subdomains)

            if not self.scan_flags.Silent:
                print(self.logger.Y + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + self.logger.W)

            if self.scan_flags.Ports:
                if not self.scan_flags.Silent:
                    print(self.logger.G + "[-] Starting port scan for the following ports: %s%s" % (self.logger.Y, self.scan_flags.Ports) + self.logger.W)
                ports = self.scan_flags.Ports.split(',')
                pscan = PortScanner(subdomains, ports)
                pscan.run()

            elif not self.scan_flags.Silent:
                for subdomain in subdomains:
                    print(self.logger.G + subdomain + self.logger.W)
        return subdomains
