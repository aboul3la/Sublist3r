#!/usr/bin/env python
# coding: utf-8

import re

from layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def clean_up_domain_text(parsed_domain,subdomain,verbose,self,):
	# Remove all Chinese and text before
	RE = re.compile(u'.*[^\x00-\x7F]+', re.UNICODE)
	subdomain = RE.sub('', subdomain)

	# Remove Misc Artifacts
	subdomain = re.sub('https?://|[|]|“|<(\/)?kw>|<(\/)?em>|<(\/)?strong>|<(\/)?b>|u\'|\', |\'|.+?<p>|<span.*?>|\*|"|;|<|mailto:|Email:|:|\\(|&lt;|&#39|{|}|', '', subdomain.lower())
	remove_list = {'32':'split','}':'split','&quot':'split','>':'split','&amp;':'split','>':'split',',':'split','+':'split','/':'split','.':'strip',' ':'split'}
	for i, j in remove_list.items():
		# Check is any characters are in remove list
		if j is "split":
			subdomain = subdomain.rsplit(i, 1)[-1]
		else:
			subdomain = subdomain.strip(i)

	if parsed_domain.netloc not in subdomain and subdomain:
		subdomain = subdomain+'.'+parsed_domain.netloc

	if subdomain not in self.subdomains and '...' not in subdomain and subdomain != self.domain and subdomain:
		if verbose:
			print "%s%s: %s%s"%(R, self.engine_name, W, subdomain)
		self.subdomains.append(subdomain)
