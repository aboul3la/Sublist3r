#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
from collections import Counter

# external modules
from scan_flags import ScanParams
from subbrute import subbrute
import dns.resolver
import requests

# Python 2.x and 3.x compatiablity
from subscann3r import SubScann3r
from util.logger import Logger

if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')
logger = Logger(is_windows, False)

def parser_error(errmsg):
    logger.banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(logger.R + "Error: " + errmsg + logger.W)
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?',
                        default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int,
                        default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    return parser.parse_args()


def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    logger.is_verbose = verbose
    options = ScanParams(silent=silent, verbose=verbose, brute_force=enable_bruteforce, thread_count=threads, engines=engines, ports=ports, savefile=savefile)
    scanner = SubScann3r(domain, logger, options)
    return scanner.scan()


if __name__ == "__main__":
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    engines = args.engines
    if verbose or verbose is None:
        verbose = True
    logger.banner()
    res = main(domain, threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce, engines=engines)
