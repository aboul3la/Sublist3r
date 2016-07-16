#!/usr/bin/env python
# coding: utf-8

import multiprocessing
import threading
import requests
import re
import urlparse

from ..layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

class DomainSearch(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        global verbose
        verbose = subdomains
        subdomains = subdomains or []
        self.base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "ThreatCrowd"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 20
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print G+"[-] Searching now in %s.." %(self.engine_name)+W
        return

    def req(self, url):
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        }

        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)

    def get_response(self,response):
    	if response is None:
    		return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            import json
        except Exception as e:
            print e
            return


        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass
