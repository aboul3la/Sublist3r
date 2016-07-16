#!/usr/bin/env python
# coding: utf-8

import multiprocessing
import requests
import sys
import threading
import urlparse

#Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

#Console Colors
if is_windows:
    G = Y = B = R = W = G = Y = B = R = W = '' #use no terminal colors on windows
else:
    G = '\033[92m' #green
    Y = '\033[93m' #yellow
    B = '\033[94m' #blue
    R = '\033[91m' #red
    W = '\033[0m'  #white

class enumratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 10
        self.base_url = base_url
        self.engine_name = engine_name
        self.print_banner()

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        print G+"[-] Searching now in %s.." %(self.engine_name)+W
        return

    def send_req(self, query, page_no=1):
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
        }

        url =  self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            resp = None
            pass
        return self.get_response(resp)

    def get_response(self,response):
    	if response is None:
    		return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def check_max_subdomains(self,count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    #Override
    def extract_domains(self, resp):
        """ chlid class should override this function """
        return

    #override
    def check_response_errors(self, resp):
        """ chlid class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumrators require sleeping to avoid bot detections like Google enumerator"""
        return

    def generate_query(self):
        """ chlid class should override this function """
        return

    def get_page(self, num):
        """ chlid class that user different pagnation counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        prev_subdomains = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain) #finding the number of subdomains found so far

            #if they we reached the maximum number of subdomains in search query
            #then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no): #maximum pages for Google to avoid getting blocked
                return self.subdomains
            resp = self.send_req(query, page_no)

            #check if there is any error occured
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

        #if the previous page hyperlinks was the similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

        #make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains

class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
