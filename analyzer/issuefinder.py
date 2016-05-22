import psycopg2
import logging
from OpenSSL import crypto

class IssueFinder:
	def __init__(self, db):
		self.first_cert_dnsname_counter = 0
		self.first_cert_cn_counter = 0
		self.ca_switch_counter = 0
		self.early_renewal_counter = 0
		self.weaker_crypto_keysize_counter = 0
		self.weaker_crypto_algorithm_counter = 0
		self.rfc_violation_counter = 0
		self.db = db

	def get_all_cn(self):
		logging.debug("calling get_all_cn")
		
		return self._get_result_list("SELECT DISTINCT NAME_VALUE FROM certificate_identity WHERE NAME_TYPE='commonName'")
	
	def get_all_dnsname(self):
		logging.debug("calling get_all_dnsname")
		
		return self._get_result_list("SELECT DISTINCT NAME_VALUE FROM certificate_identity WHERE NAME_TYPE='dNSName'")
	
	
	def get_history_for_cn(self, cn):
		logging.debug("calling get_history_for_cn")
		
		return self._get_result_list("SELECT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE))=reverse(lower(%s)) ORDER BY x509_notBefore(CERTIFICATE) ASC", (cn,))
	
	
	def _get_result_list(self, query, parameters=None):
		logging.debug("calling _get_result_list")
		
		result = []
		with self.db.cursor() as cursor:
			logging.debug("Setting cursor.arraysize to 2000")
			cursor.arraysize = 2000
			
			logging.debug("Querying database")
			if(parameters == None):
				cursor.execute(query)
			else:
				cursor.execute(query, parameters)
			
			logging.debug("Fetching results")
			while True:
				rows = cursor.fetchmany() # fetch 'arraysize' many results
				#logging.debug("Fetched {0} entries".format(len(rows)))
				if(rows):
					result += rows
				else:
					logging.debug("Exiting loop")
					break
		return result
	
	
	def check_weaker_crypto_algorithm(self, ordered_list_of_certificates):
		"""ctobs.issues.weaker_crypto_algorithm"""
		logging.debug("calling check_weaker_crypto_algorithm")
		
		ordering = {}
		ordering['sha1WithRSAEncryption'] = 100
		ordering['sha256WithRSAEncryption'] = 1000
		
		result = []
		
		last_order = 0
		for ID, certificate_bin, ca_id in ordered_list_of_certificates:
			certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
			current_algorithm = certificate.get_signature_algorithm()
			
			current_order = 0
			if(current_algorithm in ordering):
				current_order = ordering[current_algorithm]
			else:
				logging.warning("unknown algorithm: '{0}'".format(current_algorithm))
				
			if(current_order < last_order):
				result.append(ID)
			last_order = ordering[current_algorithm]
			logging.debug("Last order is {0} ({1})".format(ordering[current_algorithm], current_algorithm))
		return result
	
	def check_weaker_crypto_keysize(self, ordered_list_of_certificates):
		"""ctobs.issues.weaker_crypto_keysize"""
		logging.debug("calling check_weaker_crypto_keysize")
		
		ordering = {}
		ordering['sha1WithRSAEncryption'] = 100
		ordering['sha256WithRSAEncryption'] = 1000
		
		result = []
		
		last_order = 0
		last_keysize = 0
		for ID, certificate_bin, ca_id in ordered_list_of_certificates:
			logging.debug("loading certificate")
			certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
			current_algorithm = certificate.get_signature_algorithm()
			current_keysize = certificate.get_pubkey().bits()
			
			current_order = 0
			if(current_algorithm in ordering):
				current_order = ordering[current_algorithm]
			else:
				logging.warning("unknown algorithm: '{0}'".format(current_algorithm))
				
			if(current_order == last_order):
				if(current_keysize < last_keysize):
					result.append(ID)
			last_order = ordering[current_algorithm]
			last_keysize = current_keysize
			logging.debug("Last order is {0} ({1}), last keysize is {2}".format(last_order, current_algorithm, last_keysize))
		return result
	
	
	def testing(self):
		
		#./analyzer.py --pg=ctdatabase --es=elasticsearch --web=ctobservatory -d -i
		all_cn = self.get_all_cn()
		print("Fetched all CN values: {0} in total.".format(len(all_cn)))
		for i in range(100):
			print(all_cn[i])
			
		all_dnsname = self.get_all_dnsname()
		print("Fetched all dNSName values: {0} in total.".format(len(all_dnsname)))
		for i in range(100):
			print(all_dnsname[i])
			
		ggl_history = self.get_history_for_cn("www.google.com")
		print("Fetched all history values: {0} in total.".format(len(ggl_history)))
		
		weaker_ggl_crypto_algorithm = self.check_weaker_crypto_algorithm(ggl_history)
		weaker_ggl_crypto_keysize = self.check_weaker_crypto_keysize(ggl_history)
		
		
			
		return "{{'testing':'done', 'weaker_crypto_algorithm_counter':{0}, 'weaker_crypto_keysize_counter':{1}}}".format(len(weaker_ggl_crypto_algorithm), len(weaker_ggl_crypto_keysize))
