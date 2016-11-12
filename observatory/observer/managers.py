from django.db import models
from OpenSSL import crypto
import datetime


class Sha256Digest(models.Transform):
    lookup_name = 'sha256'

    def as_sql(self, compiler, connection):
        lhs, lhs_params = compiler.compile(self.lhs)
        return "digest(%s, 'sha256')" % lhs, lhs_params

models.Field.register_lookup(Sha256Digest)
