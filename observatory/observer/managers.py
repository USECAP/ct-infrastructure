from django.db import models
from OpenSSL import crypto
import datetime

class NotBefore(models.Transform):
    lookup_name = 'not_before'
    function = 'x509_notBefore'

    @property
    def output_field(self):
        return models.DateField()

models.BinaryField.register_lookup(NotBefore)

class NotAfter(models.Transform):
    lookup_name = 'not_after'
    function = 'x509_notAfter'

    @property
    def output_field(self):
        return models.DateField()

models.BinaryField.register_lookup(NotAfter)

class CommonName(models.Transform):
    lookup_name = 'common_name'
    function = 'x509_commonName'

    @property
    def output_field(self):
        return models.TextField()

models.BinaryField.register_lookup(CommonName)


class Sha256Digest(models.Transform):
    lookup_name = 'sha256'

    def as_sql(self, compiler, connection):
        lhs, lhs_params = compiler.compile(self.lhs)
        return "digest(%s, 'sha256')" % lhs, lhs_params

models.Field.register_lookup(Sha256Digest)


class CertificateManager(models.Manager):


    def get_active(self):
        from .models import RevokedCertificate #we can't import this globally as .models imports this file
        return super(CertificateManager,self).get_queryset().filter(certificate__not_after__gt=datetime.datetime.now()).filter(certificate__not_before__lt=datetime.datetime.now()).exclude(id__in = RevokedCertificate.objects.values_list('id', flat=True))

    def get_expired(self):
        return super(CertificateManager,self).get_queryset().filter(certificate__not_after__lt=datetime.datetime.now())

    def get_revoked(self):
        from .models import RevokedCertificate #we can't import this globally as .models imports this file
        return super(CertificateManager,self).get_queryset().filter(id__in = RevokedCertificate.objects.values_list('id', flat=True))

    def find_by_organization_name(self,term):
        return None
        term = "%{0}%".format(term)
        return self.raw("SELECT ID, CERTIFICATE, ISSUER_CA_ID FROM CERTIFICATE WHERE x509_issuerName(CERTIFICATE) LIKE %s", [term])
