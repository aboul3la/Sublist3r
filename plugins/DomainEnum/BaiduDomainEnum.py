#!/usr/bin/env python
# coding: utf-8

#Issues

import random
import re
import time
import urlparse

from ..cleanup import *
from collections import Counter
from ..processor import enumratorBaseThreaded
from ..layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

class DomainSearch(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        global verbose
        global parsed_domain
        parsed_domain = urlparse.urlparse(domain)
        verbose = subdomains
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 5
        self.MAX_PAGES = 760
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name,domain, subdomains, q=q)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)/&nbsp;</a>')
        links_list = link_regx.findall(resp)
        for link in links_list:
            clean_up_domain_text(parsed_domain,link,verbose,self)
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links_list

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query
