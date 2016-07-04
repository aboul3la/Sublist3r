#!/usr/bin/env python
# coding: utf-8
# SubList3r v0.1
# By Ahmed Aboul-Ela - twitter.com/aboul3la

import re
import sys
import os
import argparse
import time
import requests
import urlparse
import urllib
import hashlib
import random
import multiprocessing
import threading
import dns.resolver
import socket
from subbrute import subbrute
from collections import Counter
from Queue import Queue

#In case you cannot install some of the required development packages, there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

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

def banner():
      print """%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s
                
                 # Coded By Ahmed Aboul-Ela - @aboul3la
    """%(R,W,Y)

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
            pass
        return self.get_response(resp)

    def get_response(self,response):
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


class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link="http://"+link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass
        return links_list

    def check_response_errors(self, resp):
        if 'Our systems have detected unusual traffic' in resp:
            print R+"[!] Error: Google probably now is blocking our requests"+W
            print R+"[~] Finished now the Google Enumeration ..."+W
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS-2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

class YahooEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name,domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx2 = re.compile('<span class=" fz-15px fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links+links2
            for link in links_list:
                link = re.sub("<(\/)?b>","", link)
                if not link.startswith('http'):
                    link="http://"+link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass

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

class AskEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link="http://"+link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass

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

class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name,domain, subdomains,q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links+links2

            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link="http://"+link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query


class BaiduEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name,domain, subdomains, q=q)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link="http://"+link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if verbose:
                            print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                        self.subdomains.append(subdomain)
        except Exception as e:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

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

class NetcraftEnum(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
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
            raise
        return resp

    def get_response(self,response):
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
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass
        return links_list


class DNSdumpster(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://dnsdumpster.com/'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.live_subdomains = []
        self.session = requests.Session()
        self.engine_name = "DNSdumpster"
        multiprocessing.Process.__init__(self)
        self.threads = 70
        self.lock = threading.BoundedSemaphore(value=self.threads)
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

    def check_host(self,host):
        is_valid = False
        Resolver = dns.resolver.Resolver()
        Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.lock.acquire()
        try:
            ip = Resolver.query(host, 'A')[0].to_text()
            if ip:
                if verbose:
                    print "%s%s: %s%s"%(R, self.engine_name, W, host)
                is_valid = True
                self.live_subdomains.append(host)
        except:
            pass
        self.lock.release()
        return is_valid

    def req(self, req_method, url, params=None):
        params = params or {}
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': 'https://dnsdumpster.com'
        }

        try:
            if req_method == 'GET':
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=params, headers=headers, timeout=self.timeout)
        except Exception as e:
            print e
            raise
        return self.get_response(resp)

    def get_response(self,response):
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content
        
    def get_csrftoken(self, resp):
        csrf_regex = re.compile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />",re.S)
        token = csrf_regex.findall(resp)[0]
        return token.strip()

    def enumerate(self):
        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        params = {'csrfmiddlewaretoken':token, 'targetip':self.domain}
        post_resp = self.req('POST', self.base_url, params)
        self.extract_domains(post_resp)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.check_host,args=(subdomain,))
            t.start()
            t.join()
        return self.live_subdomains
    

    def extract_domains(self, resp):
        tbl_regex = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>',re.S)
        link_regex = re.compile('<td class="col-md-4">(.*?)<br>',re.S)
        links = []
        try:
            results_tbl = tbl_regex.findall(resp)[0]
        except IndexError:
            results_tbl = ''
        links_list = link_regex.findall(results_tbl)
        links = list(set(links_list))
        for link in links:
            subdomain = link.strip()
            if not subdomain.endswith(self.domain):
                continue
            if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                self.subdomains.append(subdomain)
        return links

class Virustotal(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://www.virustotal.com/en/domain/{domain}/information/'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "Virustotal"
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
            
        return self.get_response(resp)

    def get_response(self,response):
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
        link_regx = re.compile('<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>',re.S)
        try:
            links = link_regx.findall(resp)
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
        
        

class CrtSearch(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
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
            return 0
            
        return self.get_response(resp)

    def get_response(self,response):
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
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain) or '*' in subdomain:
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
        except Exception as e:
            pass
        
class PassiveDNS(multiprocessing.Process):
    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
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
            return 0
            
        return self.get_response(resp)

    def get_response(self,response):
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
                subdomain = link[:link.find('[')]
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
                    self.subdomains.append(subdomain)
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
                s.settimeout(1)
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
def main():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    google_list = []
    bing_list = []
    baidu_list = []
    bruteforce_list = set()
    search_list = set()
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
    enums = [enum(domain, verbose, q=subdomains_queue) for enum in BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum, NetcraftEnum, DNSdumpster, Virustotal, CrtSearch, PassiveDNS]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()
    
    subdomains =  set(subdomains_queue)
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
            pscan = portscan(subdomains,ports)
            pscan.run()
            
        else:
            for subdomain in subdomains:
                print G+subdomain+W
                
if __name__=="__main__":
    main()
