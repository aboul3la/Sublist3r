#!/usr/bin/env python
# coding: utf-8

import multiprocessing
import re
import requests
import threading
import urlparse

from ..cleanup import *
from ..layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

class DomainSearch(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        global verbose
        global parsed_domain
        parsed_domain = urlparse.urlparse(domain)
        verbose = subdomains
        subdomains = subdomains or []
        self.base_url = 'https://crt.sh/?q=%25.{domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "SSL Certificates"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 25
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
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<TD>(.*?)</TD>')
        links_list = link_regx.findall(resp)
        for link in links_list:
            clean_up_domain_text(parsed_domain,link,verbose,self)
