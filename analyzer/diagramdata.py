import urllib
import urlparse
import shutil
import logging
import os
import ssl
import threading
import datetime
import json
import psycopg2

class Diagramdata(threading.Thread):
	def __init__(self, baseurl, target_directory, dbname, dbuser, dbhost, disable_tls_security, force_replace=False):
		threading.Thread.__init__(self)
		self.baseurl = baseurl
		self.target_directory = target_directory
		self.dbname = dbname
		self.dbuser = dbuser
		self.dbhost = dbhost
		self.disable_tls_security = disable_tls_security
		self.force_replace = force_replace
		self.logger = logging.getLogger(__name__)
		self.analysis_key = "diagram_last_id"
	
	def run(self):
            self.update_diagrams()
		
	def replace_data(self, url, filename):
		request_url = urlparse.urljoin(self.baseurl, url)
		target_filename = os.path.join(self.target_directory, filename)
		target_filename_dl = os.path.join(self.target_directory, "{}.dl".format(filename))
		
		self.logger.debug("Retrieving {url}, saving as {path_dl}".format(url=request_url, path_dl=target_filename_dl))
		
		if(self.disable_tls_security):
			c = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
			urllib.urlretrieve(request_url, target_filename_dl, context=c)
		else:
			urllib.urlretrieve(request_url, target_filename_dl)
		
		self.logger.debug("Copying file {path_dl} to {path}".format(path_dl=target_filename_dl, path=target_filename))
		
		with open(target_filename_dl, 'r') as f_in:
			try:
				content = json.load(f_in)
				if 'data' in content:
					shutil.copy(target_filename_dl, target_filename)
					self.logger.debug("File {path} has been saved".format(path=target_filename))
				else:
					self.logger.error("File {} does not have a data section!".format(path_dl))
			except ValueError:
				self.logger.error("File {} is not a json object!".format(target_filename_dl))
			
	
	def update_json_ca(self, target_file, update_data_file):
		try:
			target = None
			update = None
			update_data = None
			with open(target_file, 'r') as f_target, open(update_data_file, 'r') as f_update:
				target = json.load(f_target)
				update = json.load(f_update)
				update_data = update['data']
			
			# update cas in the target
			cas_in_target = set()
			for ca_t in target['data']:
				ca_id = ca_t['key']
				if(ca_id != 'other'):
					cas_in_target.add(ca_id)
					
					if(ca_id in update_data):
						for values in ca_t:
							month = values[0]
							if month in update_data[ca_id]:
								new_value = values[1] + update_data[ca_id][month]
								values = [month, new_value]
							
			
			
			#update 'other'
			for ca_t in target['data']:
				ca_id = ca_t['key']
				if(ca_id == 'other'):
					for ca_id in (set(update_data.keys()) - cas_in_target):
						for values in ca_t:
							month = values[0]
							if month in update_data[ca_id]:
								new_value = values[1] + update_data[ca_id][month]
								values = [month, new_value]
				
			
			with open(target_file, 'w') as f_target:
				json.dump(target, f_target)
			
				
				
			return True
		except Exception as e:
			self.logger.exception(e)
			return False
	
	def update_json_keysize(self, target_file, update_data_file):
		try:
			target = None
			update = None
			update_data = None
			with open(target_file, 'r') as f_target, open(update_data_file, 'r') as f_update:
				target = json.load(f_target)
				update = json.load(f_update)
				update_data = update['data']
			
			# update keysizes in the target
			keysizes_in_target = set()
			for keysize in target['data']:
				keysize_id = keysize['key']
				if(keysize_id != 'other'):
					keysizes_in_target.add(keysize_id)
					
					if(keysize_id in update_data):
						new_value = keysize['values'][0]['value'] + update_data[keysize_id]
						keysize['values'][0]['value'] = new_value
							
			#update 'other'
			for keysize in target['data']:
				keysize_id = keysize['key']
				if(keysize_id == 'other'):
					for ks_id in (set(update_data.keys()) - keysizes_in_target):
						new_value = keysize['values'][0]['value'] + update_data[ks_id]
						keysize['values'][0]['value'] = new_value
			
			with open(target_file, 'w') as f_target:
				json.dump(target, f_target)
			
				
				
			return True
		except Exception as e:
			self.logger.exception(e)
			return False
	
	def update_data(self, url, filename, merge_function):
		request_url = urlparse.urljoin(self.baseurl, url)
		target_filename = os.path.join(self.target_directory, filename)
		target_filename_dl = os.path.join(self.target_directory, "{}.dl".format(filename))
		
		from_id = 0
		
		if(os.path.isfile(target_filename)):
			with open(target_filename, "r") as f:
				data = json.load(f)
				from_id = data['max_id']
		
		self.logger.debug("Retrieving {url} into {path_dl}, updating {path}".format(url=request_url.format(from_id), path=target_filename, path_dl=target_filename_dl))
		
		if(not os.path.isfile(target_filename)):
			self.logger.error("File {path} does not exist! Call again with --force-replace parameter to create it before trying to update it.".format(path=target_filename))
			return
		
		if(self.disable_tls_security):
			c = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
			urllib.urlretrieve(request_url.format(from_id), target_filename_dl, context=c)
		else:
			urllib.urlretrieve(request_url.format(from_id), target_filename_dl)
			
		self.logger.debug("File {path_dl} has been saved".format(path_dl=target_filename_dl))
		
		if merge_function(target_filename, target_filename_dl):
			self.logger.debug("Successfully merged new data into {path}".format(path=target_filename))
		else:
			self.logger.error("Could not merge new data into {path}!".format(path=target_filename))
		
		
	def update_diagrams(self):
		
		db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
		cursor = db.cursor()
		
		from_id = 0
		to_id   = 0
		if(not self.force_replace):
			cursor.execute("SELECT value FROM certificate_analysis WHERE type=%s", [self.analysis_key])
			retval = cursor.fetchone()
			if(retval):
				from_id = retval[0]
			
		cursor.execute("SELECT max(id) FROM certificate")
		retval = cursor.fetchone()
		if(retval):
			to_id = retval[0]
		
		self.logger.debug("Updating getloginfo... {0}".format(datetime.datetime.now()))
		self.replace_data("/api/getloginfo", 'getloginfo')
		
		self.logger.debug("Updating getlogdist... {0}".format(datetime.datetime.now()))
		self.replace_data("/api/getlogdist", 'getlogdist')
		
		self.logger.debug("Updating getcadistribution... {0}".format(datetime.datetime.now()))
		if(self.force_replace):
			self.replace_data("/api/getcadistribution", 'getcadistribution')
		else:
			self.update_data("/api/getcadistribution/from/{0}", 'getcadistribution', self.update_json_ca)
		
		self.logger.debug("Updating getactivekeysizedistribution... {0}".format(datetime.datetime.now()))
		if(self.force_replace):
			self.replace_data("/api/getactivekeysizedistribution", 'getactivekeysizedistribution')
		else:
			self.update_data("/api/getactivekeysizedistribution/from/{0}", 'getactivekeysizedistribution', self.update_json_keysize)
			
		
		self.logger.debug("Updating getsignaturealgorithmdistribution... {0}".format(datetime.datetime.now()))
		if(self.force_replace):
			self.replace_data("/api/getsignaturealgorithmdistribution", 'getsignaturealgorithmdistribution')
		else:
			self.update_data("/api/getsignaturealgorithmdistribution/from/{0}", 'getsignaturealgorithmdistribution', self.update_json_ca)
		
		self.logger.debug("Setting {} to {}".format(self.analysis_key, to_id))
		
		self.logger.debug("Done (Diagramdata.update_diagrams). {0}".format(datetime.datetime.now()))
		
		self.logger.info( "Updated diagrams." )
		db.close()