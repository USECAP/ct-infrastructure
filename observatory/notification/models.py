from __future__ import unicode_literals

from django.db import models

class Notification_dns_names(models.Model):
    name=models.TextField(default='')

class Notification_email(models.Model):
    email=models.TextField(default='')
    validate_key=models.TextField(default='')
    validated=models.BooleanField(default=False)
    active=models.BooleanField(default=False)
    dns_name=models.ForeignKey(Notification_dns_names)




