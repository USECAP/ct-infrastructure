import psycopg2
import re
import urllib2
from OpenSSL import crypto


class RevokedCertificateAnalyzer:
    def __init__(self, db):
        self.revoke_counter = 0
        self.found_in_database_counter = 0
        self.updated_counter = 0
        self.db = db
        
    def refresh_crls(self):
        for crl_url in self.get_crl_urls_out_of_certificate_extensions():
            self.download_and_parse_crl(crl_url)
        return self.print_log()

    def download_and_parse_crl(self, url):
        try:
            crlraw = urllib2.urlopen(url).read()
            self.parse_crl(crlraw)
        except Exception as e:
            pass

    def get_url_from_certificate(self, certificate):
        for e_idx in range(0, certificate.get_extension_count()):
            try:
                m = re.search('https?:\/\/([\w\.\-\/]*)\.crl(\??[\w\.\-\/=&]*)', str(certificate.get_extension(e_idx)))
                if m: return m.group(0)
            except Exception as e:
                pass
        return ""

    def get_crl_urls_out_of_certificate_extensions(self):
        crl_urls = []
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT c.certificate FROM ca_certificate cac inner join certificate c on cac.certificate_id = c.id")
        for cert in cursor.fetchall():
            decoded_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert[0]))
            crlurl = self.get_url_from_certificate(decoded_x509)
            if crlurl: crl_urls.append(crlurl)
        return set(crl_urls)

    def parse_crl(self, crlraw):
        revoked_certs = crypto.load_crl(crypto.FILETYPE_ASN1, crlraw).get_revoked()
        if revoked_certs != None:
            self.analyze_revoked_certificates(revoked_certs)
        return

    def analyze_revoked_certificates(self, certificates):
        cursor = self.db.cursor()
        for certificate in certificates:
            self.revoke_counter += 1
            cursor.execute(
                "SELECT c.id, (rc is null) as isNotLogged  from certificate c LEFT OUTER JOIN revoked_certificate rc on rc.certificate_id = c.id WHERE x509_serialNumber(c.CERTIFICATE) = %s",
                ("\\x" + certificate.get_serial(),))
            if cursor.rowcount > 0:
                self.found_in_database_counter += 1
                certificate_with_identic_serial = cursor.fetchone()
                if certificate_with_identic_serial[1]:
                    self.updated_counter += 1
                    cursor.execute("INSERT INTO revoked_certificate (certificate_id, date, reason) VALUES (%s,%s,%s)", (
                    certificate_with_identic_serial[0], str(certificate.get_rev_date())[:8],
                    str(certificate.get_reason())))
        self.db.commit()

    def print_log(self):
        return "{{'type':'revokedcerts','data':{{'found':{},'knew':{},'updated':{} }} }},".format(self.revoke_counter,self.found_in_database_counter,self.updated_counter)
