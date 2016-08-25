import string

from django.shortcuts import render, redirect
from django.core.mail import send_mail
from .forms import SubscribeUnsubscribeForm
import uuid

from .models import *

from django.http import HttpResponse

def index(request, dnsname=""):
    subscribeform = SubscribeUnsubscribeForm(initial={'name':dnsname})
    unsubscribeform = SubscribeUnsubscribeForm(initial={'name':dnsname})
    return render(request, 'notification/index.html', {'subscribeform' : subscribeform, 'unsubscribeform': unsubscribeform})

def subscribe(request):
    subscribeform = SubscribeUnsubscribeForm(request.POST)
    
    if subscribeform.is_valid():
        
        mail = subscribeform.cleaned_data['email']
        name = subscribeform.cleaned_data['name']
        mode = 0
        request.session['email'] = mail

        dns, created = NotificationDnsNames.objects.get_or_create(name=name)
        email, created  = dns.notificationemail_set.get_or_create(email=mail, notify_for=(mode if mode else 0))
        email.validate_key = str(uuid.uuid1()).replace('-','')
        email.save()
        dns.save()
        text = 'You receive this mail because you want to register for news about issued certificates for the name \''+name+'\'.\n\nPlease click the following link to complete your registration: \n\nhttp'+('s' if request.is_secure() else '') +'://'+request.get_host()+'/notification/subscription/confirm/'+str(email.id)+'/'+email.validate_key+' \n\nGreetings\nThe CT-Observatory Team'
        send_mail("CT-Observatory: Your registration for '"+name+"'",text,'info@ct-observatory.org',[mail])

        return redirect('/?subok')

    else:
        unsubscribeform = SubscribeUnsubscribeForm()
        return render(request, 'notification/index.html', {'subscribeform' : subscribeform, 'unsubscribeform': unsubscribeform})
    
    

def unsubscribe(request):
    unsubscribeform = SubscribeUnsubscribeForm(request.POST)
    
    if unsubscribeform.is_valid():
        mail = unsubscribeform.cleaned_data['email']
        name = unsubscribeform.cleaned_data['name']
        email = NotificationEmail.objects.filter(email=mail, notification_dns_names__name=name).first()

        email.validate_key = str(uuid.uuid1()).replace('-','')
        email.save()
        text = 'You receive this mail because you want to unregister for news about issued certificates for the name \''+name+'\'.\n\nPlease click the following link to complete your removal from our list: \n\nhttp'+('s' if request.is_secure() else '') +'://'+request.get_host()+'/notification/subscription/remove/'+str(email.id)+'/'+email.validate_key+' \n\nGreetings\nThe CT-Observatory Team'
        send_mail("CT-Observatory: Your unsubscription for '"+name+"'",text,'info@ct-observatory.org',[mail])

        return redirect('/?unsubok')
        
    else:
        subscribeform = SubscribeUnsubscribeForm()
        return render(request, 'notification/index.html', {'subscribeform' : subscribeform, 'unsubscribeform': unsubscribeform})
    
    

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