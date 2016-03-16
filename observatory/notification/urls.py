from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^subscribe$', views.subscribe, name='subscribe'),
    url(r'^unsubscribe$', views.unsubscribe, name='unsubscribe'),
    url(r'^subscription/confirm$', views.confirmsubscription , name='confirmsubscription'),
    url(r'^subscription/remove$', views.confirmremoval, name='confirmremoval'),
]