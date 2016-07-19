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
        self.base_url = 'http://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "Netcraft"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 10
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

    def req(self, url, cookies=None):
        cookies = cookies or {}
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout,cookies=cookies)
        except Exception as e:
            print e
            resp = None
        return resp

    def get_response(self,response):
    	if response is None:
    		return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub('host=.*?%s'%self.domain, 'host=%s'%self.domain, link[0])
        url = 'http://searchdns.netcraft.com'+link
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1])).hexdigest()
        return cookies

    def get_cookies(self,headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url,cookies))
            self.extract_domains(resp)
            if not 'Next page' in resp:
                return self.subdomains
                break
            url = self.get_next(resp)

    def extract_domains(self, resp):
        link_regx = re.compile('<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
        links_list = link_regx.findall(resp)
        for link in links_list:
            clean_up_domain_text(parsed_domain,link,verbose,self)
        return links_list
