import psycopg2
import logging
from OpenSSL import crypto
from dateutil import parser

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
	
	
	def check_first_cert_dnsname(self, ordered_list_of_certificates):
		"""ctobs.issues.first_cert_dnsname"""
		logging.debug("calling check_first_cert_dnsname")
		
		return self._get_first_certificates(ordered_list_of_certificates)
		
		
	def check_first_cert_cn(self, ordered_list_of_certificates):
		"""ctobs.issues.first_cert_cn"""
		logging.debug("calling check_first_cert_cn")
		
		return self._get_first_certificates(ordered_list_of_certificates)
	
	def _get_first_certificates(self, ordered_list_of_certificates):
		logging.debug("calling _get_first_certificates")
		
		result = []
		
		first_timestamp_str = crypto.load_certificate(crypto.FILETYPE_ASN1, str(ordered_list_of_certificates[0][1])).get_notBefore()
		first_timestamp = parser.parse(first_timestamp_str)
		logging.debug("First timestamp is {0}".format(first_timestamp))
		
		for ID, certificate_bin, ca_id in ordered_list_of_certificates:
			certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
			current_timestamp_str = certificate.get_notBefore()
			current_timestamp = parser.parse(current_timestamp_str)
			
			if(current_timestamp == first_timestamp):
				result.append(ID)
			else:
				# the certificates are ordered, so there will 
				# be no certificate with a smaller timestamp
				break
		return result
	
	def check_ca_switch(self, ordered_list_of_certificates):
		"""ctobs.issues.ca_switch"""
		logging.debug("calling check_ca_switch")
		
		result = []
		
		last_ca = ordered_list_of_certificates[0][2]
		for ID, certificate_bin, ca_id in ordered_list_of_certificates:
			
			if(ca_id != last_ca):
				logging.debug("CA switched from {0} to {1} at ID {2}".format(last_ca, ca_id, ID))
				result.append(ID)
			last_ca = ca_id
			logging.debug("Last ca is {0}".format(last_ca))
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
		#all_cn = self.get_all_cn()
		#print("Fetched all CN values: {0} in total.".format(len(all_cn)))
		#for i in range(100):
			#print(all_cn[i])
			
		#all_dnsname = self.get_all_dnsname()
		#print("Fetched all dNSName values: {0} in total.".format(len(all_dnsname)))
		#for i in range(100):
			#print(all_dnsname[i])
			
		ggl_cn_history = self.get_history_for_cn("www.google.com")
		print("Fetched all cn history values: {0} in total.".format(len(ggl_cn_history)))
		ggl_dnsname_history = self.get_history_for_cn("www.google.com")
		print("Fetched all dNSName history values: {0} in total.".format(len(ggl_dnsname_history)))
		
		weaker_ggl_cn_crypto_algorithm = self.check_weaker_crypto_algorithm(ggl_cn_history)
		weaker_ggl_cn_crypto_keysize = self.check_weaker_crypto_keysize(ggl_dnsname_history)
		
		first_ggl_cn_certificate = self.check_first_cert_cn(ggl_cn_history)
		first_ggl_dnsname_certificate = self.check_first_cert_dnsname(ggl_dnsname_history)
		
		print(first_ggl_cn_certificate)
		print(first_ggl_dnsname_certificate)
		
		ggl_cn_ca_switch = self.check_ca_switch(ggl_cn_history)
		ggl_dnsname_ca_switch = self.check_ca_switch(ggl_dnsname_history)
		
		print(ggl_cn_ca_switch)
		print(ggl_dnsname_ca_switch)
		
			
		return "{{'testing':'done', 'weaker_crypto_algorithm_counter':{0}, 'weaker_crypto_keysize_counter':{1}, 'first_cn_certificate_counter':{2}, 'first_dnsname_certificate_counter':{3}, 'ca_switch_counter':{4}}}".format(len(weaker_ggl_cn_crypto_algorithm), len(weaker_ggl_cn_crypto_keysize), len(first_ggl_cn_certificate), len(first_ggl_dnsname_certificate), len(ggl_cn_ca_switch)+len(ggl_dnsname_ca_switch))
