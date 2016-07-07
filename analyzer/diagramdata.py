import urllib
import urlparse
import shutil
import logging
import os
import ssl
import threading

class Diagramdata(threading.Thread):
	def __init__(self, baseurl, target_directory,debug):
		threading.Thread.__init__(self)
		self.baseurl = baseurl
		self.target_directory = target_directory
		self.debug = debug
	
	def run(self):
            self.update_diagrams()
		
	def update_data(self, url, filename):
		request_url = urlparse.urljoin(self.baseurl, url)
		target_filename = os.path.join(self.target_directory, filename)
		
		logging.debug("Retrieving {url}, saving as {path}".format(url=request_url, path=target_filename))
		
		if(self.debug):
			c = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
			urllib.urlretrieve(request_url, target_filename, context=c)
		else:
			urllib.urlretrieve(request_url, target_filename)
			
		logging.debug("File {path} has been saved".format(path=target_filename))
		
		
	def update_diagrams(self):
		logging.debug("Updating getloginfo...")
		self.update_data("/api/getloginfo", 'getloginfo')
		
		logging.debug("Updating getlogdist...")
		self.update_data("/api/getlogdist", 'getlogdist')
		
		logging.debug("Updating getcadistribution...")
		self.update_data("/api/getcadistribution", 'getcadistribution')
		
		logging.debug("Updating getactivekeysizedistribution...")
		self.update_data("/api/getactivekeysizedistribution", 'getactivekeysizedistribution')
		
		logging.debug("Updating getsignaturealgorithmdistribution...")
		self.update_data("/api/getsignaturealgorithmdistribution", 'getsignaturealgorithmdistribution')
		
		logging.debug("Done (Diagramdata.update_diagrams).")
		
		return "Successfully updated diagrams."