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
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(DomainSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('([^>]+).<b>'+parsed_domain.netloc.split('.')[0]+'</b>.*?'+parsed_domain.netloc.rsplit('.',1)[1]+'</b>')
        links = link_regx.findall(resp)
        links_list = links

        for link in links_list:
            # Check if span class is not in link
            if "span class=" not in link:
                clean_up_domain_text(parsed_domain,link,verbose,self)
        return links_list

    def should_sleep(self):
        return

    def get_page(self,num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query
