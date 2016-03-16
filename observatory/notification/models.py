from __future__ import unicode_literals

from django.db import models

class NotificationDnsNames(models.Model):
    name=models.TextField(default='')
    class Meta:
        managed = False
        db_table = 'notification_dns_names'

class NotificationEmail(models.Model):
    email=models.TextField(default='')
    validate_key=models.TextField(default='')
    validated=models.BooleanField(default=False)
    active=models.BooleanField(default=False)
    dns_name=models.ForeignKey(NotificationDnsNames)

    class Meta:
        managed = False
        db_table = 'notification_email'




