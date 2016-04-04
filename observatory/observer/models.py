# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin sqlcustom [app_label]'
# into your database.
from __future__ import unicode_literals
from OpenSSL import crypto
from django.db import models
from .managers import CertificateManager
import re

class Ca(models.Model):
    name = models.TextField()
    public_key = models.BinaryField()
    brand = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ca'
    
    def get_name_info(self, identifier):
        info = "-"
        m = re.search('{0}=(.*?)(,|$)'.format(identifier), self.name)
        if(m != None):
            info = m.group(1)
        else:
            m = re.search('{0}="(.*?)"(,|$)'.format(identifier), self.name)
            if(m != None):
                info = m.group(1)
        return info
    
    def get_name_C(self):
        return self.get_name_info("C")
    
    def get_name_CN(self):
        return self.get_name_info("CN")
    
    def get_name_L(self):
        return self.get_name_info("L")
    
    def get_name_O(self):
        return self.get_name_info("O")
    
    def get_name_OU(self):
        return self.get_name_info("OU")
    
    def get_name_ST(self):
        return self.get_name_info("ST")
    
    def get_name_emailAddress(self):
        return self.get_name_info("emailAddress")

class CaCertificate(models.Model):
    certificate = models.ForeignKey('Certificate')
    ca = models.ForeignKey(Ca, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ca_certificate'


class Certificate(models.Model):
    certificate = models.BinaryField()
    issuer_ca = models.ForeignKey(Ca)
    objects = CertificateManager()
    expired=models.BooleanField(default=False)
    class Meta:
        managed = False
        db_table = 'certificate'
    
    def get_certificate_data(self):
        data = []
        cert = self.get_x509_data()
        data.append(('pubkey_bits', cert.get_pubkey().bits()))
        data.append(('pubkey_type', self.pubkey_type(cert)))
        data.append(('serial_number', cert.get_serial_number()))
        data.append(('signature_algorithm', self.signature_algorithm(cert)))
        data.append(('notBefore', self.not_before(cert)))
        data.append(('notAfter', self.not_after(cert)))
        data.append(('has_expired', self.has_expired(cert)))
        data.append(('digest_md5', cert.digest('md5'.encode('ascii','ignore'))))
        data.append(('digest_sha1', cert.digest('sha1'.encode('ascii','ignore'))))
        return data

    def has_expired(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        if(cert.has_expired()):
            return True
        return False
    
    def signature_algorithm(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        return cert.get_signature_algorithm()
    
    def not_before(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = cert.get_notBefore()
        datestring = "{year}-{month}-{day} {hour}:{minute}:{seconds}".format(year=date[:4], month=date[4:6], day=date[6:8], hour=date[8:10], minute=date[10:12], seconds=date[12:14])
        return datestring
    
    def not_after(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = cert.get_notAfter()
        datestring = "{year}-{month}-{day} {hour}:{minute}:{seconds}".format(year=date[:4], month=date[4:6], day=date[6:8], hour=date[8:10], minute=date[10:12], seconds=date[12:14])
        return datestring
    
    def startdate(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = cert.get_notBefore()
        # Beware, JavaScript wants month to be zero-based (i.e. 0=January etc.)
        datestring = "{year}, {month}, {day}, {hour}, {minute}, {seconds}".format(year=int(date[:4]), month=(int(date[4:6])-1), day=int(date[6:8]), hour=int(date[8:10]), minute=int(date[10:12]), seconds=int(date[12:14]))
        return datestring
    
    def enddate(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = cert.get_notAfter()
        # Beware, JavaScript wants month to be zero-based (i.e. 0=January etc.)
        datestring = "{year}, {month}, {day}, {hour}, {minute}, {seconds}".format(year=int(date[:4]), month=(int(date[4:6])-1), day=int(date[6:8]), hour=int(date[8:10]), minute=int(date[10:12]), seconds=int(date[12:14]))
        return datestring
    
    def pubkey_type(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        pkeytype = cert.get_pubkey().type()
        if(pkeytype == crypto.TYPE_RSA):
            return "RSA"
        if(pkeytype == crypto.TYPE_DSA):
            return "DSA"
        return pkeytype

    def organization_name(self):
        cert = self.get_x509_data()
        return cert.get_issuer().commonName
    
    def subject_country_name(self):
        cert = self.get_x509_data()
        return cert.get_subject().countryName
    
    def subject_state_or_province_name(self):
        cert = self.get_x509_data()
        return cert.get_subject().stateOrProvinceName
    
    def subject_localityName(self):
        cert = self.get_x509_data()
        return cert.get_subject().localityName
    
    def subject_organization_name(self):
        cert = self.get_x509_data()
        return cert.get_subject().organizationName
    
    def subject_organizational_unit_name(self):
        cert = self.get_x509_data()
        return cert.get_subject().organizationalUnitName
    
    def subject_common_name(self):
        cert = self.get_x509_data()
        return cert.get_subject().commonName
    
    def subject_email_address(self):
        cert = self.get_x509_data()
        return cert.get_subject().emailAddress
    
    def get_subject_data(self):
        cert = self.get_x509_data()
        return cert.get_subject().get_components()
    
    def get_issuer_data(self):
        cert = self.get_x509_data()
        return cert.get_issuer().get_components()

    def get_x509_data(self):
        return crypto.load_certificate(crypto.FILETYPE_ASN1, str(self.certificate))

class CertificateIdentity(models.Model):
    certificate = models.ForeignKey(Certificate)
    name_type = models.TextField()  # This field type is a guess.
    name_value = models.TextField()
    issuer_ca = models.ForeignKey(Ca, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'certificate_identity'

class CtLog(models.Model):
    url = models.TextField(unique=True, blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    public_key = models.BinaryField(blank=True, null=True)
    latest_entry_id = models.IntegerField(blank=True, null=True)
    latest_update = models.DateTimeField(blank=True, null=True)
    operator = models.TextField(blank=True, null=True)
    included_in_chrome = models.IntegerField(blank=True, null=True)
    is_active = models.NullBooleanField()
    latest_sth_timestamp = models.DateTimeField(blank=True, null=True)
    mmd_in_seconds = models.IntegerField(blank=True, null=True)
    chrome_issue_number = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ct_log'


class CtLogEntry(models.Model):
    certificate = models.ForeignKey(Certificate)
    ct_log = models.ForeignKey(CtLog)
    entry_id = models.IntegerField()
    entry_timestamp = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ct_log_entry'

class InvalidCertificate(models.Model):
    certificate = models.ForeignKey(Certificate)
    problems = models.TextField(blank=True, null=True)
    certificate_as_logged = models.BinaryField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'invalid_certificate'

class RevokedCertificate(models.Model):
    certificate = models.ForeignKey(Certificate)
    date = models.DateTimeField(blank=True, null=True)
    reason = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'revoked_certificate'
