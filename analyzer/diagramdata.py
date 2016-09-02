import urllib
import urlparse
import shutil
import logging
import os
import ssl
import threading

class Diagramdata(threading.Thread):
	def __init__(self, baseurl, target_directory, disable_tls_security):
		threading.Thread.__init__(self)
		self.baseurl = baseurl
		self.target_directory = target_directory
		self.disable_tls_security = disable_tls_security
		self.logger = logging.getLogger(__name__)
	
	def run(self):
            self.update_diagrams()
		
	def update_data(self, url, filename):
		request_url = urlparse.urljoin(self.baseurl, url)
		target_filename = os.path.join(self.target_directory, filename)
		
		self.logger.debug("Retrieving {url}, saving as {path}".format(url=request_url, path=target_filename))
		
		if(self.disable_tls_security):
			c = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
			urllib.urlretrieve(request_url, target_filename, context=c)
		else:
			urllib.urlretrieve(request_url, target_filename)
			
		self.logger.debug("File {path} has been saved".format(path=target_filename))
		
		
	def update_diagrams(self):
		self.logger.debug("Updating getloginfo...")
		self.update_data("/api/getloginfo", 'getloginfo')
		
		self.logger.debug("Updating getlogdist...")
		self.update_data("/api/getlogdist", 'getlogdist')
		
		self.logger.debug("Updating getcadistribution...")
		self.update_data("/api/getcadistribution", 'getcadistribution')
		
		self.logger.debug("Updating getactivekeysizedistribution...")
		self.update_data("/api/getactivekeysizedistribution", 'getactivekeysizedistribution')
		
		self.logger.debug("Updating getsignaturealgorithmdistribution...")
		self.update_data("/api/getsignaturealgorithmdistribution", 'getsignaturealgorithmdistribution')
		
		self.logger.debug("Done (Diagramdata.update_diagrams).")
		
		self.logger.info( "Successfully updated diagrams." )