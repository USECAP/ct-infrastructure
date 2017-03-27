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
import codecs
import re


class Ca(models.Model):
    country_name = models.TextField(blank=True, null=True)
    state_or_province_name = models.TextField(blank=True, null=True)
    locality_name = models.TextField(blank=True, null=True)
    organization_name = models.TextField(blank=True, null=True)
    organizational_unit_name = models.TextField(blank=True, null=True)
    common_name = models.TextField(blank=True, null=True)
    email_address = models.TextField(blank=True, null=True)
    public_key = models.BinaryField()

    class Meta:
        managed = False
        db_table = 'ca'
        unique_together = (('common_name', 'public_key'),)
    
    def public_key_hex(self):
        return codecs.encode(self.public_key, 'hex')

class CaCertificate(models.Model):
    certificate = models.ForeignKey('Certificate', models.DO_NOTHING, blank=True, null=True)
    ca = models.ForeignKey(Ca, models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ca_certificate'


class Certificate(models.Model):
    certificate = models.BinaryField()
    issuer_ca = models.ForeignKey(Ca, models.DO_NOTHING)
    serial = models.BinaryField()
    sha256 = models.TextField(unique=True)
    not_before = models.DateTimeField(blank=True, null=True)
    not_after = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'certificate'
    
    def get_certificate_data(self):
        data = []
        cert = self.get_x509_data()
        try:
            data.append(('pubkey_bits', cert.get_pubkey().bits()))
        except crypto.Error:
            data.append(('pubkey_bits', None))
        data.append(('pubkey_type', self.pubkey_type(cert)))
        data.append(('serial_number', cert.get_serial_number()))
        data.append(('signature_algorithm', self.signature_algorithm(cert)))
        data.append(('notBefore', self.notbefore(cert)))
        data.append(('notAfter', self.notafter(cert)))
        data.append(('has_expired', self.has_expired(cert)))
        data.append(('digest_md5', str(cert.digest('md5')).replace(':','').lower()[2:-1]))
        data.append(('digest_sha1', str(cert.digest('sha1')).replace(':','').lower()[2:-1]))
        data.append(('digest_sha256', str(cert.digest('sha256')).replace(':','').lower()[2:-1]))
        return data

    def has_expired(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        return cert.has_expired()
    
    def signature_algorithm(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        try:
            return cert.get_signature_algorithm()
        except ValueError:
            return '__UndefinedSignatureAlgorithm__'
    
    def notbefore(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = str(cert.get_notBefore())
        datestring = "{year}-{month}-{day} {hour}:{minute}:{seconds}".format(year=date[2:6], month=date[6:8], day=date[8:10], hour=date[10:12], minute=date[12:14], seconds=date[14:16])
        return datestring
    
    def notafter(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = str(cert.get_notAfter())
        datestring = "{year}-{month}-{day} {hour}:{minute}:{seconds}".format(year=date[2:6], month=date[6:8], day=date[8:10], hour=date[10:12], minute=date[12:14], seconds=date[14:16])
        return datestring
    
    def startdate(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = str(cert.get_notBefore())
        # Beware, JavaScript wants month to be zero-based (i.e. 0=January etc.)
        datestring = "{year}, {month}, {day}, {hour}, {minute}, {seconds}".format(year=int(date[2:6]), month=(int(date[6:8])-1), day=int(date[8:10]), hour=int(date[10:12]), minute=int(date[12:14]), seconds=int(date[14:16]))
        return datestring
    
    def enddate(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        date = str(cert.get_notAfter())
        # Beware, JavaScript wants month to be zero-based (i.e. 0=January etc.)
        datestring = "{year}, {month}, {day}, {hour}, {minute}, {seconds}".format(year=int(date[2:6]), month=(int(date[6:8])-1), day=int(date[8:10]), hour=int(date[10:12]), minute=int(date[12:14]), seconds=int(date[14:16]))
        return datestring
    
    def pubkey_type(self, cert=None):
        if(cert == None):
            cert = self.get_x509_data()
        pkeytype = ""
        try:
            pkeytype = cert.get_pubkey().type()
            if(pkeytype == crypto.TYPE_RSA):
                return "RSA"
            if(pkeytype == crypto.TYPE_DSA):
                return "DSA"
        except crypto.Error:
            pkeytype = "__UndefinedKeyAlgorithm__"
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

    def get_digest_sha256(self):
        cert = self.get_x509_data()
        return cert.digest('sha256')

    def get_x509_data(self):
        return crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(self.certificate))


class CertificateIdentity(models.Model):
    certificate = models.ForeignKey(Certificate, models.DO_NOTHING)
    name_type = models.TextField()  # This field type is a guess.
    name_value = models.TextField()
    
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
    is_active = models.NullBooleanField()
    latest_sth_timestamp = models.DateTimeField(blank=True, null=True)
    latest_log_size = models.IntegerField(blank=True, null=True)
    mmd_in_seconds = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ct_log'


class CtLogEntry(models.Model):
    certificate = models.ForeignKey('Certificate', models.DO_NOTHING, blank=True, null=True)
    ct_log = models.ForeignKey('CtLog', models.DO_NOTHING, blank=True, null=True)
    entry_id = models.IntegerField(blank=True, null=True)
    entry_timestamp = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ct_log_entry'
        unique_together = (('certificate', 'ct_log', 'entry_id'),)


class RevokedCertificate(models.Model):
    certificate = models.ForeignKey('Certificate', models.DO_NOTHING, blank=True, null=True)
    date = models.DateTimeField(blank=True, null=True)
    reason = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'revoked_certificate'


class Metadata(models.Model):
    name_type = models.TextField(unique=True, blank=True, null=True)
    name_value = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'metadata'
