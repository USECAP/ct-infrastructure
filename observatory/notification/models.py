from __future__ import unicode_literals

from django.db import models

class NotificationDnsNames(models.Model):
    name=models.TextField(default='')
    class Meta:
        managed = False
        db_table = 'notification_dns_names'

class NotificationEmail(models.Model):
    email=models.TextField(default='')
    notify_for=models.IntegerField(default=0)
    validate_key=models.TextField(default='')
    validated=models.BooleanField(default=False)
    active=models.BooleanField(default=False)
    notification_dns_names=models.ForeignKey(NotificationDnsNames, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'notification_email'




