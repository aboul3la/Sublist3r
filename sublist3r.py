#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la

import argparse
import multiprocessing
import os
import re
import requests
import sys
import urllib
import urlparse

from plugins import check
from plugins.DomainEnum import AskDomainEnum
from plugins.DomainEnum import BaiduDomainEnum
from plugins.DomainEnum import BingDomainEnum
from plugins.DomainEnum import CrtDomainEnum
from plugins.DomainEnum import DNSdumpsterDomainEnum
from plugins.DomainEnum import GoogleDomainEnum
from plugins.DomainEnum import NetcraftDomainEnum
from plugins.DomainEnum import PassiveDNSDomainEnum
from plugins.DomainEnum import ThreatCrowdDomainEnum
from plugins.DomainEnum import VirustotalDomainEnum
from plugins.DomainEnum import YahooDomainEnum

from Queue import Queue
from subbrute import subbrute

#In case you cannot install some of the required development packages, there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

from plugins.layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def parser_error(errmsg):
    banner()
    print "Usage: python "+sys.argv[0]+" [Options] use -h for help"
    print R+"Error: "+errmsg+W
    sys.exit()

def parse_args():
    #parse the arguments
    parser = argparse.ArgumentParser(epilog = '\tExample: \r\npython '+sys.argv[0]+" -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumrate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module',nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime',nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-o', '--output', help='Save the results to text file')
    return parser.parse_args()

def write_file(filename, subdomains):
    #saving subdomains results to output file
    print "%s[-] Saving results to file: %s%s%s%s"%(Y,W,R,filename,W)
    with open(str(filename), 'wb') as f:
        for subdomain in subdomains:
            f.write(subdomain+"\r\n")

def main():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    bruteforce_list = set()
    search_list = set()

    #Check if we are running this on windows platform
    is_windows = sys.platform.startswith('win')

    if is_windows:
        subdomains_queue = list()
    else:
        subdomains_queue = multiprocessing.Manager().list()

    #Check Verbosity
    global verbose
    verbose = args.verbose
    if verbose or verbose is None:
        verbose = True

    #Check Bruteforce Status
    enable_bruteforce = args.bruteforce
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    #Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        print R+"Error: Please enter a valid domain"+W
        sys.exit()

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://'+domain

    #Print the Banner
    banner()
    parsed_domain = urlparse.urlparse(domain)

    print B+"[-] Enumerating subdomains now for %s"%parsed_domain.netloc+W

    if verbose:
        print Y+"[-] verbosity is enabled, will show the subdomains results in realtime"+W

    #Start the engines enumeration
    enums = [enum(domain, verbose, q=subdomains_queue) for enum in AskDomainEnum.DomainSearch, BaiduDomainEnum.DomainSearch, BingDomainEnum.DomainSearch, CrtDomainEnum.DomainSearch, DNSdumpsterDomainEnum.DomainSearch, GoogleDomainEnum.DomainSearch, NetcraftDomainEnum.DomainSearch, PassiveDNSDomainEnum.DomainSearch, ThreatCrowdDomainEnum.DomainSearch, VirustotalDomainEnum.DomainSearch, YahooDomainEnum.DomainSearch,]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        print G+"[-] Starting bruteforce module now using subbrute.."+W
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
        resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        process_count = threads
        output = False
        json_output = False
        bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count, output, json_output, search_list, verbose)

    subdomains = search_list.union(bruteforce_list)

    if subdomains:
        subdomains = sorted(subdomains)
        if savefile:
            write_file(savefile, subdomains)

        print Y+"[-] Total Unique Subdomains Found: %s"%len(subdomains)+W

        if ports:
            print G+"[-] Start port scan now for the following ports: %s%s"%(Y,ports)+W
            ports = ports.split(',')
            pscan = check.portscan(subdomains,ports)
            pscan.run()

        else:
            for subdomain in subdomains:
                print G+subdomain+W

if __name__=="__main__":
    main()
