from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^change$', views.index, name='index'),
    url(r'^change/(?P<dnsname>.+)$', views.index, name='index'),
    url(r'^subscribe$', views.subscribe, name='subscribe'),
    url(r'^unsubscribe$', views.unsubscribe, name='unsubscribe'),
    url(r'^subscription/confirm/(?P<mail_id>[0-9]+)/(?P<token>[\w-]+)$', views.confirmsubscription , name='confirmsubscription'),
    url(r'^subscription/remove/(?P<mail_id>[0-9]+)/(?P<token>[\w-]+)$', views.confirmremoval, name='confirmremoval'),
]