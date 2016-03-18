import string

from django.shortcuts import render, redirect
from django.core.mail import send_mail
import uuid

from .models import *


def index(request, dnsname=""):
    return render(request, 'notification/index.html', {'dnsname': dnsname})

def subscribe(request):
    mail = request.POST['email']
    dnsname = request.POST['dnsname']
    mode = request.POST['notifyfor']
    request.session['email'] = mail

    if dnsname :
        dns, created = NotificationDnsNames.objects.get_or_create(name=dnsname)
        email, created  = dns.notificationemail_set.get_or_create(email=mail, notify_for=(mode if mode else 0))
        email.validate_key = str(uuid.uuid1()).replace('-','')
        email.save()
        dns.save()
        text = 'You receive this mail because you want to register for news about issued certificates for the domain '+dnsname+'.\n\n Please click the following link to complete your registration: <a href="http'+('s' if request.is_secure() else '') +'://'+request.get_host()+'/notification/subscription/confirm/'+str(email.id)+'/'+email.validate_key+'">subscribe</a> \n\nGreetings\nThe CT-Observatory-Team'
        send_mail("CT-Observatory: Your registration for DNS-Name '"+dnsname+"'",text,'info@ct-observatory.org',[mail], html_message=text.replace('\n','<br/>'))

    return render(request, 'notification/yougotmail.html')

def unsubscribe(request):
    mail = request.POST['email']
    dnsname = request.POST['dnsname']
    email = NotificationEmail.objects.filter(email=mail, notification_dns_names__name=dnsname).first()
    if email:
        email.validate_key = str(uuid.uuid1()).replace('-','')
        email.save()
        text = 'You receive this mail because you want to unregister for news about issued certificates for the domain '+dnsname+'.\n\n Please click the following link to complete your removal from our list: <a href="http'+('s' if request.is_secure() else '') +'://'+request.get_host()+'/notification/subscription/remove/'+str(email.id)+'/'+email.validate_key+'">unsubscribe</a> \n\nGreetings\nThe CT-Observatory-Team'
        send_mail("CT-Observatory: Your registration for DNS-Name '"+dnsname+"'",text,'info@ct-observatory.org',[mail], html_message=text.replace('\n','<br/>'))
        return render(request, 'notification/yougotmail.html')
    return redirect('/')

def confirmsubscription(request, mail_id, token):
    email = NotificationEmail.objects.filter(id=mail_id, validate_key=token).first()
    if email:
        email.validated = True
        email.active = True
        email.save()
        return render(request, 'notification/subscriptionsuccessful.html', {'email': email})
    return redirect('/')

def confirmremoval(request, mail_id, token):
    result = NotificationEmail.objects.filter(id=mail_id, validate_key=token).delete()
    if result[0] == 1:
        return render(request, 'notification/removalsuccessful.html')
    return redirect('/')