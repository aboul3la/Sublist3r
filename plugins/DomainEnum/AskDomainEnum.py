#!/usr/bin/env python
# coding: utf-8

import re
import urlparse

from ..cleanup import *
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
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<p class="web-result-url">(.*?).'+parsed_domain.netloc)
        link_regx2 = re.compile('<p class="rightrail-web-result-url">(.*?)</p>')
        links = link_regx.findall(resp)
        links2 = link_regx2.findall(resp)
        links_list = links+links2
        for link in links_list:
            clean_up_domain_text(parsed_domain,link,verbose,self)

        return links_list

    def get_page(self,num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)

        return query
