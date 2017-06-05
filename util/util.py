import socket
import threading

import requests
import re


class Util:
    def subdomain_sorting_key(hostname):
        """Sorting key for subdomains
    
        This sorting key orders subdomains from the top-level domain at the right
        reading left, then moving '^' and 'www' to the top of their group. For
        example, the following list is sorted correctly:
    
        [
            'example.com',
            'www.example.com',
            'a.example.com',
            'www.a.example.com',
            'b.a.example.com',
            'b.example.com',
            'example.net',
            'www.example.net',
            'a.example.net',
        ]
    
        """
        parts = hostname.split('.')[::-1]
        if parts[-1] == 'www':
            return parts[:-1], 1
        return parts, 0

    def write_file(self, filename, subdomains):
        # saving subdomains results to output file
        print("%s[-] Saving results to file: %s%s%s%s" % (Y, W, R, filename, W))
        with open(str(filename), 'wt') as f:
            for subdomain in subdomains:
                f.write(subdomain + "\r\n")

    def get_url_signatures(url):
        service_signatures = {
            'Heroku': '<iframe src="//www.herokucdn.com/error-pages/no-such-app.html"></iframe>',
            'GitHub Pages': '<p> If you\'re trying to publish one, <a href="https://help.github.com/pages/">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>',
            'Squarespace': '<title>Squarespace - No Such Account</title>',
            'Shopify': '<div id="shop-not-found"> <h1 class="tc">Sorry, this shop is currently unavailable.</h1> </div>',
            'Zendesk': '<span class="title">Bummer. It looks like the help center that you are trying to reach no longer exists.</span>',
            'GitLab': '<head> <title>The page you\'re looking for could not be found (404)</title> <style> body { color: #666; text-align: center; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; margin: 0; width: 800px; margin: auto; font-size: 14px; } h1 { font-size: 56px; line-height: 100px; font-weight: normal; color: #456; } h2 { font-size: 24px; color: #666; line-height: 1.5em; } h3 { color: #456; font-size: 20px; font-weight: normal; line-height: 28px; } hr { margin: 18px 0; border: 0; border-top: 1px solid #EEE; border-bottom: 1px solid white; } </style> </head>'
        }
        data = Util.get_url_data(url)
        if data == 0:
            return []
        # Strip newlines
        data = data.replace('\n', '').replace('\r', '')
        data = re.sub("\s\s+", ' ', data);
        results = []
        for name in service_signatures:
            if service_signatures[name] in data:
                results.append(name)
        return results

    def get_url_data(url, timeout=25):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        try:
            resp = requests.Session().get(url, headers=headers, timeout=timeout)
        except Exception:
            resp = None
        if resp is None:
            return 0
        return resp.text if hasattr(resp, "text") else resp.content
