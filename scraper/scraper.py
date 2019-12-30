from bs4 import BeautifulSoup as bs
import requests
import os
import sys
from socket import socket, gethostbyname
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import urllib3
import random, string
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
"""
Consider:
- 401,403,404 errors, which should be parsed as well.
- 405 (not implemented) errors, which should be very strange, since GET is standard.
- 500 (Server error).
- 301/302/303 and follow the redirect, with a limit in case the redirect is broken.
- Css, javascript and images should be downloaded.
"""

def get_https_name(domain, port): #This code doesn't need to consider http codes, since it's in an upper layer.
    sock = socket()
    sock.connect((domain, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    sock_ssl = SSL.Connection(ctx, sock)
    try:
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(bytes(domain,'utf-8'))
        sock_ssl.do_handshake()
    except SSL.Error:
        sock_ssl.close()
        sock.close()
        return None
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    names = ""
    try:
        names = crypto_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except x509.ExtensionNotFound:
        return None
    sock_ssl.close()
    sock.close()
    return names[0].value

def get_valid_urls(domain, ports, include_ip=True):
    urls = []
    for port in ports:
        url = get_https_name(domain, int(port))
        if url is not None:
            url = "https://" + domain + ":" + str(port)
            if include_ip:
                urls.append("https://" + gethostbyname(domain) + ":" + str(port))
        else:
            url = "http://" + domain + ":" + str(port)
            if include_ip:
                urls.append("http://" + gethostbyname(domain) + ":" + str(port))
        if url not in urls:
            urls.append(url)
    return urls

def appifnotNone(obj, obj2):
    if obj2 is not None:
        obj.extend(obj2)

def containsChild(obj, child):
    try:
        obj[child] = obj[child]
    except:
        return False
    return True

def downloadExternals(exts, url):
    out = list()
    for ext in exts:
        source = ""
        if containsChild(ext, "src"):
            source = ext["src"]
        elif containsChild(ext, "href"):
            source = ext["href"]
        else:
            continue
        if source.startswith("http"):
            data = requests.get(source, verify=False)
        else:
            ext_url = url + "/" + source
            ext_url = ext_url.replace("//","/").replace(":/","://")
            data = requests.get(ext_url, verify=False)
        out.append((ext, data.content))
    return out

def saveExternals(exts):
    for ext,data in exts:
        if ext.name == "script":
            ext['src'] = "script" + os.sep + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".js"
            with open("output" + os.sep + ext['src'],'wb') as f:
                f.write(data)
        elif ext.name == "img":
            ext['src']= "img" + os.sep + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".img"
            with open("output" + os.sep + ext['src'],'wb') as f:
                f.write(data)
        else:
            ext['href'] = "css" + os.sep + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".css"
            with open("output" + os.sep + ext['href'],'wb') as f:
                f.write(data)

def createIfNotExists():
    try:
        os.mkdir("output")
    except:
        pass
    try:
        os.mkdir("output" + os.sep + "script")
    except:
        pass
    try:
        os.mkdir("output" + os.sep + "img")
    except:
        pass
    try:
        os.mkdir("output" + os.sep + "css")
    except:
        pass

def scrape_url(url):
    createIfNotExists()
    req = requests.get(url, verify=False)
    soup = bs(req.text, "html.parser")
    ext = []
    appifnotNone(ext, soup.find_all('script'))
    appifnotNone(ext, soup.find_all('img'))
    appifnotNone(ext, soup.find_all('link'))
    ext = downloadExternals(ext, url)
    saveExternals(ext)
    finalname = url.replace("/","_").replace(":","_")
    with open("output" + os.sep + finalname, "w") as f:
        f.write(soup.prettify())
    

if __name__ == '__main__':
    urls = get_valid_urls("support.hackerone.com", [443],False)
    for url in urls:
        scrape_url(url)