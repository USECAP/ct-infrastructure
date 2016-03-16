from django.shortcuts import render
from django.core.mail import send_mail
import uuid

from .models import Notification_email, Notification_dns_names


def index(request):
    return render(request, 'notification/index.html')

def subscribe(request):
    mail = request.POST['email']
    dnsname = request.POST['dnsname']

    if dnsname :
        dns, created = Notification_dns_names.objects.get_or_create(name=dnsname)
        email, created  = dns.notification_email_set.get_or_create(email=mail,defaults={'validate_key':uuid.uuid1()})
        send_mail("CT-Observatory: Your registration for DNS-Name '"+dnsname+"'",
                  'You receive this mail because you want to register for news about issued certificates for the domain '+dnsname+'.\n\n '
                  'Please click the following link to complete your registration: '+request.path+'/subscription/confirm?mail='+mail+'&token='+email.validate_key+' \n\n'
                  'Greetings\nThe CT-Observatory-Team',
                  'info@ct-observatory.org',
                  [email])
        email.save()
        dns.save()


def unsubscribe(request):
    mail = request.POST['email']
    dnsname = request.POST['dnsname']

    pass

def confirmsubscription(request):
    pass

def confirmremoval(request):
    pass