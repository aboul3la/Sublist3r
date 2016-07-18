#!/usr/bin/env python
# coding: utf-8

import multiprocessing
import re
import requests
import threading
import urlparse

from ..layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

class DomainSearch(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        global verbose
        verbose = subdomains
        subdomains = subdomains or []
        self.base_url = 'http://ptrarchive.com/tools/search.htm?label={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "PassiveDNS"
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
            print e
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
        link_regx = re.compile('<td>(.*?)</td>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                if self.domain not in link:
                    continue
                subdomain = link[:link.find('[')].strip()
                if subdomain not in self.subdomains and subdomain != self.domain and subdomain.endswith(self.domain):
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass

class portscan():

    def __init__(self,subdomains,ports):
        self.subdomains = subdomains
        self.ports = ports
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scan(self,host,ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close
            except Exception as e:
                pass
        self.lock.release()
        if len(openports) > 0:
            print "%s%s%s - %sFound open ports:%s %s%s%s"%(G,host,W,R,W,Y,', '.join(openports),W)

    def run(self):
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan,args=(subdomain,self.ports))
            t.start()
