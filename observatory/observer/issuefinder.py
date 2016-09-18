from OpenSSL import crypto
from dateutil import parser
from datetime import datetime
from datetime import timedelta

def _get_dns_names(certificate):
	retval = set()
	for i in range(certificate.get_extension_count()):
		e = certificate.get_extension(i)
		if("subjectAltName" == e.get_short_name()):
			dns_name_list = str(e).split(", ")
			dns_name_list = [x[4:] for x in dns_name_list]
			dns_name_set = set(dns_name_list)
			return dns_name_set
	return retval

def get_first_certificates(ordered_list_of_certificates, result={}):
	"""ctobs.issues.first_cert_dnsname"""
	"""ctobs.issues.first_cert_cn"""
	"""ctobs.issues.first_cert"""
	
	if (len(ordered_list_of_certificates) < 1):
		return result

	first_timestamp_str = crypto.load_certificate(crypto.FILETYPE_ASN1, str(ordered_list_of_certificates[0].certificate)).get_notBefore()
	first_timestamp = parser.parse(first_timestamp_str)

	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
							str(certificate_bin))
		current_timestamp_str = certificate.get_notBefore()
		current_timestamp = parser.parse(current_timestamp_str)

		if (current_timestamp == first_timestamp):
			if(ID not in result):
				result[ID] = []
			result[ID].append("ctobs.issues.first_cert")
		else:
			# the certificates are ordered, so there will
			# be no certificate with a smaller timestamp
			break
	return result

def get_ca_switch(ordered_list_of_certificates, result={}):
	"""ctobs.issues.ca_switch"""
	
	if (len(ordered_list_of_certificates) < 1):
		return result

	last_ca = ordered_list_of_certificates[0].issuer_ca.id
	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		if (ca_id != last_ca):
			if(ID not in result):
				result[ID] = []
			result[ID].append("ctobs.issues.ca_switch")
		last_ca = ca_id
	return result

def get_weaker_crypto_algorithm(ordered_list_of_certificates, result={}):
	"""ctobs.issues.weaker_crypto_algorithm"""

	ordering = {}
	ordering['sha1WithRSAEncryption'] = 100
	ordering['md5WithRSAEncryption'] = 100
	ordering['sha256WithRSAEncryption'] = 1000
	ordering['sha512WithRSAEncryption'] = 1000
	ordering['ecdsa-with-SHA256'] = 1000

	ordering['sha384WithRSAEncryption'] = 100
	ordering['dsa_with_SHA256'] = 100
	ordering['sha1WithRSA'] = 100
	ordering['ecdsa-with-SHA384'] = 1000


	last_order = 0
	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
		current_algorithm = certificate.get_signature_algorithm()

		current_order = 0
		if (current_algorithm in ordering):
			current_order = ordering[current_algorithm]
		else:
			pass # UNKNOWN algorithm

		if (current_order < last_order):
			if(ID not in result):
				result[ID] = []
			result[ID].append("ctobs.issues.weaker_crypto_algorithm")
		last_order = current_order
	return result

def get_weaker_crypto_keysize(ordered_list_of_certificates, result={}):
	"""ctobs.issues.weaker_crypto_keysize"""

	ordering = {}
	ordering['sha1WithRSAEncryption'] = 100
	ordering['md5WithRSAEncryption'] = 100
	ordering['sha256WithRSAEncryption'] = 1000
	ordering['sha512WithRSAEncryption'] = 1000
	ordering['ecdsa-with-SHA256'] = 1000

	ordering['sha384WithRSAEncryption'] = 100
	ordering['dsa_with_SHA256'] = 100
	ordering['sha1WithRSA'] = 100
	ordering['ecdsa-with-SHA384'] = 1000

	last_order = 0
	last_keysize = 0
	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
		current_algorithm = certificate.get_signature_algorithm()
		current_keysize = certificate.get_pubkey().bits()

		current_order = 0
		if (current_algorithm in ordering):
			current_order = ordering[current_algorithm]
		else:
			pass # UNKNOWN algorithm

		if (current_order == last_order):
			if (current_keysize < last_keysize):
				if(ID not in result):
					result[ID] = []
				result[ID].append("ctobs.issues.weaker_crypto_keysize")
		last_order = current_order
		last_keysize = current_keysize
	return result

def get_early_renewal(ordered_list_of_certificates, result={}):
	"""ctobs.issues.early_renewal"""

	# early = before the middle of the validity period of a previous set of certificates, and without changes to the CN, the set of DNSNames, the signature algorithm or the keysize. Kind of willy-nilly, but hey.

	minimum_diff_between_certificates = timedelta(minutes=30)


	if (len(ordered_list_of_certificates) < 1):
		return result

	first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(ordered_list_of_certificates[0].certificate))

	last_start = parser.parse(first_certificate.get_notBefore())
	last_end = parser.parse(first_certificate.get_notAfter())
	last_cn = first_certificate.get_subject().commonName
	last_dns_names = _get_dns_names(first_certificate)
	last_algorithm = first_certificate.get_signature_algorithm()
	last_keysize = first_certificate.get_pubkey().bits()
	flag_as_early = False

	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
		notbefore = parser.parse(certificate.get_notBefore())
		notafter = parser.parse(certificate.get_notAfter())
		cn = certificate.get_subject().commonName
		dns_names = _get_dns_names(certificate)
		algorithm = certificate.get_signature_algorithm()
		keysize = certificate.get_pubkey().bits()

		if ((notbefore - last_start) > minimum_diff_between_certificates):
			# new set
			flag_as_early = False
			center = (last_start + ((last_end - last_start) // 2))
			if (notbefore < center):
				# early renewal
				flag_as_early = True
				
				# do not flag as early if cn changed
				if(last_cn != cn):
					flag_as_early = False
				
				# do not flag as early if set of dnsnames changed
				if(last_dns_names != dns_names):
					flag_as_early = False
				
				# do not flag as early if algorithm changed
				if(last_algorithm != algorithm):
					flag_as_early = False
				
				# do not flag as early if keysize changed
				if(last_keysize != keysize):
					flag_as_early = False
				
			last_start = notbefore
			last_end = notafter
			last_cn = cn
			last_dns_names = dns_names
			last_algorithm = algorithm
			last_keysize = keysize

		else:
			# old set
			last_end = max(last_end, notafter)

		if (flag_as_early):
			if(ID not in result):
				result[ID] = []
			result[ID].append("ctobs.issues.early_renewal")

	return result

def get_short_validity(ordered_list_of_certificates, result={}):
	"""ctobs.issues.short_validity"""

	if (len(ordered_list_of_certificates) < 1):
		return result

	first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(ordered_list_of_certificates[0].certificate))

	first_start = parser.parse(first_certificate.get_notBefore())
	first_end = parser.parse(first_certificate.get_notAfter())
	last_duration = first_end - first_start

	durations = []

	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(certificate_bin))
		notbefore = parser.parse(certificate.get_notBefore())
		notafter = parser.parse(certificate.get_notAfter())

		duration = notafter - notbefore

		# do not warn if duration is approx. equal to last_duration

		if (abs(last_duration - duration) < last_duration // 10):  # We will allow a 10% deviation
			# ok, same duration as last one
			pass
		else:
			if (len(durations) > 4):
				# take the last 5 values,
				# discard their min and max value,
				# take the average of the remaining 3,
				# check for a 50 % decrease
				values = durations[-5:]
				values.sort()
				avg = timedelta(0)
				for x in values[1:4]:
					avg += x
				avg //= 3
				
				if (duration < (avg // 2)):
					if(ID not in result):
						result[ID] = []
					result[ID].append("ctobs.issues.short_validity")

			else:
				# we do not have 5 values yet:
				# just average the existing values,
				# check for a 50 % decrease
				avg = timedelta(0)
				for x in durations:
					avg += x
				avg //= 3

				if (duration < (avg // 2)):
					if(ID not in result):
						result[ID] = []
					result[ID].append("ctobs.issues.short_validity")

		last_duration = duration
		durations.append(duration)

	return result

def get_long_validity(ordered_list_of_certificates, result={}):
	"""ctobs.issues.long_validity"""

	if (len(ordered_list_of_certificates) < 1):
		return result

	first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(ordered_list_of_certificates[0].certificate))

	first_start = parser.parse(first_certificate.get_notBefore())
	first_end = parser.parse(first_certificate.get_notAfter())
	last_duration = first_end - first_start
	durations = []

	for certificate in ordered_list_of_certificates:
		ID = certificate.id
		certificate_bin = certificate.certificate
		ca_id = certificate.issuer_ca.id
		certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,str(certificate_bin))
		notbefore = parser.parse(certificate.get_notBefore())
		notafter = parser.parse(certificate.get_notAfter())

		duration = notafter - notbefore

		# do not warn if duration is approx. equal to last_duration

		if (abs(last_duration - duration) < last_duration // 10):  # We will allow a 10% deviation
			# ok, same duration as last one
			pass
		else:
			if (len(durations) > 4):
				# take the last 5 values,
				# discard their min and max value,
				# take the average of the remaining 3,
				# check for a 50 % increase
				values = durations[-5:]
				values.sort()
				avg = timedelta(0)
				for x in values[1:4]:
					avg += x
				avg //= 3

				if (duration > avg * 3 // 2):
					if(ID not in result):
						result[ID] = []
					result[ID].append("ctobs.issues.long_validity")


			else:
				# we do not have 5 values yet:
				# just average the existing values,
				# check for a 50 % increase
				avg = timedelta(0)
				for x in durations:
					avg += x
				avg //= len(durations)

				if (duration > avg * 3 // 2):
					if(ID not in result):
						result[ID] = []
					result[ID].append("ctobs.issues.long_validity")

		last_duration = duration
		durations.append(duration)

	return result

def get_all_issues(ordered_list_of_certificates):
	result = {}
	result = get_first_certificates(ordered_list_of_certificates, result)
	result = get_ca_switch(ordered_list_of_certificates, result)
	result = get_weaker_crypto_algorithm(ordered_list_of_certificates, result)
	result = get_weaker_crypto_keysize(ordered_list_of_certificates, result)
	result = get_early_renewal(ordered_list_of_certificates, result)
	result = get_short_validity(ordered_list_of_certificates, result)
	result = get_long_validity(ordered_list_of_certificates, result)
	return result
