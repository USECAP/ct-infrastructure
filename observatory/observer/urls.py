from django.conf.urls import url

from . import views, api

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^ca/all$', views.caall, name='caall'),
    url(r'^ca/all/(?P<page>[0-9]+)$', views.caall, name='caall'),
    url(r'^cert/all$', views.certall, name='certall'),
    url(r'^cert/all/(?P<page>[0-9]+)$', views.certall, name='certall'),
    url(r'^cert/active$', views.certactive, name='certactive'),
    url(r'^cert/active/(?P<page>[0-9]+)$', views.certactive, name='certactive'),
    url(r'^cert/expired$', views.certexpired, name='certexpired'),
    url(r'^cert/expired/(?P<page>[0-9]+)$', views.certexpired, name='certexpired'),
    url(r'^cert/expired/(?P<order>[A-Za-z]+)/(?P<page>[0-9]+)$', views.certexpired, name='certexpired'),
    url(r'^cert/revoked$', views.certrevoked, name='certrevoked'),
    url(r'^cert/revoked/(?P<page>[0-9]+)$', views.certrevoked, name='certrevoked'),
    url(r'^cert/cn/(?P<cn>.+)$', views.list_cn_certs, name='list_cn_certs'),
    url(r'^cert/dnsname/(?P<dnsname>.+)$', views.list_dnsname_certs, name='list_dnsname_certs'),
    url(r'^log$', views.log, name='log'),
    url(r'^ca/(?P<ca_id>[0-9]+)/$', views.cadetail, name='cadetail'),
    url(r'^ca/(?P<ca_id>[0-9]+)/certificates$', views.certs_by_ca, name='certs_by_ca'),
    url(r'^ca/(?P<ca_id>[0-9]+)/certificates/(?P<page>[0-9]+)$', views.certs_by_ca, name='certs_by_ca'),
    url(r'^cert/(?P<cert_id>[0-9]+)/$', views.certdetail, name='certdetail'),
    url(r'^log/(?P<log_id>[0-9]+)/certs/$', views.certs_by_log, name='certs_by_log'),
    url(r'^log/(?P<log_id>[0-9]+)/certs/(?P<page>[0-9]+)$', views.certs_by_log, name='certs_by_log'),
    url(r'^log/(?P<log_id>[0-9]+)/$', views.logdetail, name='logdetail'),
    url(r'^search$', views.search, name='search'),
    url(r'^flag/(?P<flag_id>[a-zA-Z-]*)$', views.flag, name='flag'),
    url(r'^api/getcas$', api.getcas, name='getcas'),
    url(r'^api/getcas/(?P<page>[0-9]+)$', api.getcaspage, name='getcaspage'),
    url(r'^api/getcertchain/(?P<cert_id>[0-9]+)$', api.get_certificate_chain, name='get_certificate_chain'),
    url(r'^api/ca/(?P<ca_id>[0-9]+)$', api.get_ca_chain, name='get_ca_chain'),
    url(r'^api/getlogdist$', api.get_log_appearance_distribution, name='get_log_appearance_distribution'),
    url(r'^api/getloginfo$', api.get_log_information, name='get_log_information'),
    url(r'^api/getallcertinfo$', api.get_all_cert_information, name='get_all_cert_information'),
    url(r'^api/getcertdistribution$', api.get_cert_distribution_per_year, name='get_cert_distribution_per_year'),
    url(r'^api/getactivekeysizedistribution$', api.get_active_keysize_distribution, name='get_active_keysize_distribution'),
    url(r'^api/getactivekeysizedistribution/(?P<ca_id>[0-9]+)$', api.get_active_keysize_distribution, name='get_active_keysize_distribution'),
    url(r'^api/getsignaturealgorithmdistribution$', api.get_signature_algorithm_distribution, name='get_signature_algorithm_distribution'),
    url(r'^api/getsignaturealgorithmdistribution/(?P<ca_id>[0-9]+)$', api.get_signature_algorithm_distribution, name='get_signature_algorithm_distribution'),
    url(r'^api/getcadistribution$', api.get_ca_distribution, name='get_ca_distribution'),
    url(r'^api/search/cn_dnsname/(?P<term>.+)/(?P<offset>[0-9]+)$', api.search_cn_dnsname, name='search_cn_dnsname'),
    url(r'^api/search/ca/(?P<term>.+)/(?P<offset>[0-9]+)$', api.search_ca, name='search_ca'),
    url(r'^api/search/getlastcertificates/(?P<term>.+)/(?P<limit>[0-9]*)$', api.get_last_certificates_for_dnsname, name='get_last_certificates_for_dnsname'),
    url(r'^api/search/certificateknown/(?P<fingerprint>.+)$',
        api.search_certificate_by_fingerprint,
        name='search_cert_by_fingerprint'),
    url(r'^imprint$', views.imprint, name='imprint'),

]
