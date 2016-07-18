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
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name,domain, subdomains,q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)'+parsed_domain.netloc)
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)'+parsed_domain.netloc)
        links = link_regx.findall(resp)
        links2 = link_regx2.findall(resp)
        links_list = links+links2
        for link in links_list:
            clean_up_domain_text(parsed_domain,link,verbose,self)

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query
