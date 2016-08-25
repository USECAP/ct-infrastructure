import psycopg2
import logging
from OpenSSL import crypto
from dateutil import parser
from datetime import datetime
from datetime import timedelta
import threading


class IssueFinder(threading.Thread):
    def __init__(self, dbname, dbuser, dbhost):
        threading.Thread.__init__(self)
        self.first_cert_dnsname_counter = 0
        self.first_cert_cn_counter = 0
        self.ca_switch_counter = 0
        self.early_renewal_counter = 0
        self.short_validity_counter = 0
        self.long_validity_counter = 0
        self.weaker_crypto_keysize_counter = 0
        self.weaker_crypto_algorithm_counter = 0
        self.rfc_violation_counter = 0
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.db = None
    
    def run(self):
        self.db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
        self.testing() #TODO
        self.db.close()

    def get_all_cn(self):
        logging.debug("calling get_all_cn")

        return self._get_result_list(
            "SELECT DISTINCT NAME_VALUE FROM certificate_identity WHERE NAME_TYPE='commonName'")

    def get_all_dnsname(self):
        logging.debug("calling get_all_dnsname")

        return self._get_result_list(
            "SELECT DISTINCT NAME_VALUE FROM certificate_identity WHERE NAME_TYPE='dNSName'")

    def get_history_for_cn(self, cn):
        logging.debug("calling get_history_for_cn")

        return self._get_result_list(
            "SELECT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE))=reverse(lower(%s)) ORDER BY x509_notBefore(CERTIFICATE) ASC",
            (cn,))

    def get_history_for_dnsname(self, dnsname):
        logging.debug("calling get_history_for_dnsname")

        return self._get_result_list(
            "SELECT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE))=reverse(lower(%s)) ORDER BY x509_notBefore(CERTIFICATE) ASC",
            (dnsname,))

    def _get_result_list(self, query, parameters=None):
        logging.debug("calling _get_result_list")

        result = []
        with self.db.cursor() as cursor:
            logging.debug("Setting cursor.arraysize to 2000")
            cursor.arraysize = 2000

            logging.debug("Querying database")
            if (parameters == None):
                cursor.execute(query)
            else:
                cursor.execute(query, parameters)

            logging.debug("Fetching results")
            while True:
                rows = cursor.fetchmany()  # fetch 'arraysize' many results
                # logging.debug("Fetched {0} entries".format(len(rows)))
                if (rows):
                    result += rows
                else:
                    logging.debug("Exiting loop")
                    break
        return result

    def check_first_certificates(self, ordered_list_of_certificates):
        """ctobs.issues.first_cert_dnsname"""
        """ctobs.issues.first_cert_cn"""
        logging.debug("calling check_first_certificates")

        result = []

        first_timestamp_str = crypto.load_certificate(crypto.FILETYPE_ASN1, str(
                ordered_list_of_certificates[0][1])).get_notBefore()
        first_timestamp = parser.parse(first_timestamp_str)
        logging.debug("First timestamp is {0}".format(first_timestamp))

        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            current_timestamp_str = certificate.get_notBefore()
            current_timestamp = parser.parse(current_timestamp_str)

            if (current_timestamp == first_timestamp):
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

            if (ca_id != last_ca):
                logging.debug(
                    "CA switched from {0} to {1} at ID {2}".format(last_ca,
                                                                   ca_id, ID))
                result.append(ID)
            last_ca = ca_id
            logging.debug("Last ca is {0}".format(last_ca))
        return result

    def check_weaker_crypto_algorithm(self, ordered_list_of_certificates):
        """ctobs.issues.weaker_crypto_algorithm"""
        logging.debug("calling check_weaker_crypto_algorithm")

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

        result = []

        last_order = 0
        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            current_algorithm = certificate.get_signature_algorithm()

            current_order = 0
            if (current_algorithm in ordering):
                current_order = ordering[current_algorithm]
            else:
                logging.warning(
                    "unknown algorithm: '{0}'".format(current_algorithm))

            if (current_order < last_order):
                result.append(ID)
            last_order = current_order
            logging.debug(
                "Last order is {0} ({1})".format(last_order, current_algorithm))
        return result

    def check_weaker_crypto_keysize(self, ordered_list_of_certificates):
        """ctobs.issues.weaker_crypto_keysize"""
        logging.debug("calling check_weaker_crypto_keysize")

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

        result = []

        last_order = 0
        last_keysize = 0
        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            logging.debug("loading certificate")
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            current_algorithm = certificate.get_signature_algorithm()
            current_keysize = certificate.get_pubkey().bits()

            current_order = 0
            if (current_algorithm in ordering):
                current_order = ordering[current_algorithm]
            else:
                logging.warning(
                    "unknown algorithm: '{0}'".format(current_algorithm))

            if (current_order == last_order):
                if (current_keysize < last_keysize):
                    result.append(ID)
            last_order = current_order
            last_keysize = current_keysize
            logging.debug("Last order is {0} ({1}), last keysize is {2}".format(
                last_order, current_algorithm, last_keysize))
        return result

    def check_early_renewal(self, ordered_list_of_certificates):
        """ctobs.issues.early_renewal"""

        # early = before the middle of the validity period of a previous set of certificates. Kind of willy-nilly, but hey.

        minimum_diff_between_certificates = timedelta(minutes=30)
        logging.debug("calling check_early_renewal")

        result = []

        if (len(ordered_list_of_certificates) < 1):
            logging.debug("received an empty list")
            return result

        first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(
                ordered_list_of_certificates[0][1]))

        last_start = parser.parse(first_certificate.get_notBefore())
        last_end = parser.parse(first_certificate.get_notAfter())
        flag_as_early = False

        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            logging.debug("loading certificate")
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            notbefore = parser.parse(certificate.get_notBefore())
            notafter = parser.parse(certificate.get_notAfter())

            if ((notbefore - last_start) > minimum_diff_between_certificates):
                # new set
                flag_as_early = False
                center = (
                last_start + ((last_end - last_start) // 2))
                if (notbefore < center):
                    # early renewal
                    flag_as_early = True
                last_start = notbefore
                last_end = notafter

            else:
                # old set
                last_end = max(last_end, notafter)

            if (flag_as_early):
                result.append(ID)

        return result

    def check_short_validity(self, ordered_list_of_certificates):
        """ctobs.issues.short_validity"""

        logging.debug("calling check_short_validity")

        result = []

        if (len(ordered_list_of_certificates) < 1):
            logging.debug("received an empty list")
            return result

        first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(
                ordered_list_of_certificates[0][1]))

        first_start = parser.parse(first_certificate.get_notBefore())
        first_end = parser.parse(first_certificate.get_notAfter())
        last_duration = first_end - first_start

        durations = []

        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            logging.debug("loading certificate")
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            notbefore = parser.parse(certificate.get_notBefore())
            notafter = parser.parse(certificate.get_notAfter())

            duration = notafter - notbefore

            # do not warn if duration is approx. equal to last_duration

            if (abs(
                        last_duration - duration) < last_duration // 10):  # We will allow a 10% deviation
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
                    logging.debug(
                        "id: {2} duration: {0} avg: {1}".format(duration, avg,
                                                                ID))
                    if (duration < (avg // 2)):
                        result.append(ID)


                else:
                    # we do not have 5 values yet:
                    # just average the existing values,
                    # check for a 50 % decrease
                    avg = timedelta(0)
                    for x in durations:
                        avg += x
                    avg //= 3

                    logging.debug(
                        "id: {2} duration: {0} avg: {1}".format(duration, avg,
                                                                ID))
                    if (duration < (avg // 2)):
                        result.append(ID)

            last_duration = duration
            durations.append(duration)

        return result

    def check_long_validity(self, ordered_list_of_certificates):
        """ctobs.issues.long_validity"""

        logging.debug("calling check_long_validity")

        result = []

        if (len(ordered_list_of_certificates) < 1):
            logging.debug("received an empty list")
            return result

        first_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, str(
                ordered_list_of_certificates[0][1]))

        first_start = parser.parse(first_certificate.get_notBefore())
        first_end = parser.parse(first_certificate.get_notAfter())
        last_duration = first_end - first_start
        durations = []

        for ID, certificate_bin, ca_id in ordered_list_of_certificates:
            logging.debug("loading certificate")
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                  str(certificate_bin))
            notbefore = parser.parse(certificate.get_notBefore())
            notafter = parser.parse(certificate.get_notAfter())

            duration = notafter - notbefore

            # do not warn if duration is approx. equal to last_duration

            if (abs(
                        last_duration - duration) < last_duration // 10):  # We will allow a 10% deviation
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
                        result.append(ID)


                else:
                    # we do not have 5 values yet:
                    # just average the existing values,
                    # check for a 50 % increase
                    avg = timedelta(0)
                    for x in durations:
                        avg += x
                    avg //= len(durations)

                    if (duration > avg * 3 // 2):
                        result.append(ID)

            last_duration = duration
            durations.append(duration)

        return result

    def analyzeCN(self, commonName):
        history = self.get_history_for_cn(commonName)
        field = 'commonName'

        results = {}

        results[
            'ctobs.issues.weaker_crypto_algorithm'] = self.check_weaker_crypto_algorithm(
            history)
        results[
            'ctobs.issues.weaker_crypto_keysize'] = self.check_weaker_crypto_keysize(
            history)
        results['ctobs.issues.ca_switch'] = self.check_ca_switch(history)
        results['ctobs.issues.first_cert_cn'] = self.check_first_certificates(
            history)
        results['ctobs.issues.early_renewal'] = self.check_early_renewal(
            history)
        results['ctobs.issues.long_validity'] = self.check_long_validity(
            history)
        results['ctobs.issues.short_validity'] = self.check_short_validity(
            history)

        cursor = self.db.cursor()

        logging.debug("Fetching issue ids from database")
        cursor.execute("SELECT ID, NAME FROM ISSUES")
        mapping = {}
        for ID, name in cursor.fetchall():
            mapping[name] = ID

        for key in results:
            logging.debug("Handling '{0}'".format(key))
            if (key not in mapping):
                logging.error(
                    "'{0}' has not registered as an issue in the database".format(
                        key))
            else:
                issue = mapping[key]
                for certificate in results[key]:
                    logging.debug(
                        "Inserting {0}-{1}-{2}".format(certificate, issue,
                                                       commonName))
                    cursor.execute(
                        "INSERT INTO found_issues(CERTIFICATE, ISSUE, FIELD, EXTRA) VALUES (%(certificate)s, %(issue)s, %(field)s, %(extra)s) ON CONFLICT DO NOTHING",
                        {
                            'certificate': certificate, 
                            'issue'      : issue,
                            'field'      : field, 
                            'extra'      : commonName
                            })
                    logging.debug(cursor.statusmessage)
                self.db.commit()

    def testing(self):

        # ./analyzer.py --pg=ctdatabase --es=elasticsearch --web=ctobservatory -d -i

        all_cn = self.get_all_cn()

        for i in range(len(all_cn)):
            if (i % 10000 == 0):
                logging.info(
                    "Processing cn {0} of {1} ({2})".format(i, len(all_cn),
                                                            datetime.now()))
            self.analyzeCN(all_cn[i])
        # self.analyzeCN("www.google.com")

        return '{"Jo mei":9001}'

    # all_cn = self.get_all_cn()
    # print("Fetched all CN values: {0} in total.".format(len(all_cn)))
    # for i in range(100):
    # print(all_cn[i])

    # all_dnsname = self.get_all_dnsname()
    # print("Fetched all dNSName values: {0} in total.".format(len(all_dnsname)))
    # for i in range(100):
    # print(all_dnsname[i])

    # ggl_cn_history = self.get_history_for_cn("www.google.com")
    # print("Fetched all cn history values: {0} in total.".format(len(ggl_cn_history)))
    # ggl_dnsname_history = self.get_history_for_cn("www.google.com")
    # print("Fetched all dNSName history values: {0} in total.".format(len(ggl_dnsname_history)))

    # weaker_ggl_cn_crypto_algorithm = self.check_weaker_crypto_algorithm(ggl_cn_history)
    # weaker_ggl_cn_crypto_keysize = self.check_weaker_crypto_keysize(ggl_dnsname_history)

    # first_ggl_cn_certificate = self.check_first_certificates(ggl_cn_history)
    # first_ggl_dnsname_certificate = self.check_first_certificates(ggl_dnsname_history)

    # print(first_ggl_cn_certificate)
    # print(first_ggl_dnsname_certificate)

    # ggl_cn_ca_switch = self.check_ca_switch(ggl_cn_history)
    # ggl_dnsname_ca_switch = self.check_ca_switch(ggl_dnsname_history)

    # print(ggl_cn_ca_switch)
    # print(ggl_dnsname_ca_switch)

    # ggl_cn_early_renewal = self.check_early_renewal(ggl_cn_history)
    # ggl_dnsname_early_renewal = self.check_early_renewal(ggl_dnsname_history)

    # print(ggl_cn_early_renewal)
    # print(ggl_dnsname_early_renewal)

    # ggl_cn_long_validity = self.check_long_validity(ggl_cn_history)
    # ggl_dns_long_validity = self.check_long_validity(ggl_dnsname_history)

    # print(ggl_cn_long_validity)
    # print(ggl_dns_long_validity)

    # ggl_cn_short_validity = self.check_short_validity(ggl_cn_history)
    # ggl_dns_short_validity = self.check_short_validity(ggl_dnsname_history)

    # print(ggl_cn_short_validity)
    # print(ggl_dns_short_validity)


    # return "{{'testing':'done', 'weaker_crypto_algorithm_counter':{0}, 'weaker_crypto_keysize_counter':{1}, 'first_cn_certificate_counter':{2}, 'first_dnsname_certificate_counter':{3}, 'ca_switch_counter':{4}, 'early_renewal_counter':{5}, 'long_validity_counter':{6}, 'short_validity_counter':{7}}}".format(len(weaker_ggl_cn_crypto_algorithm), len(weaker_ggl_cn_crypto_keysize), len(first_ggl_cn_certificate), len(first_ggl_dnsname_certificate), len(ggl_cn_ca_switch)+len(ggl_dnsname_ca_switch), len(ggl_cn_early_renewal)+len(ggl_dnsname_early_renewal), len(ggl_cn_long_validity)+len(ggl_dns_long_validity), len(ggl_cn_short_validity)+len(ggl_dns_short_validity))
