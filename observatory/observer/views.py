from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.db.models import Count
from django.db.models import QuerySet
from django.db import connection
from django.core.paginator import Paginator,  PageNotAnInteger
from django.http import HttpResponse
from django.http import HttpResponsePermanentRedirect
import datetime
import os
import json
from ctobservatory.settings import BASE_DIR
from .models import *
from notification.forms import SubscribeUnsubscribeForm
#from .issuefinder import *
import observer.issuefinder as issuefinder
from django.template.defaulttags import register
import hashlib
ITEMS_PER_PAGE = 50

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

class FastCountQuerySet():
    def __init__(self, queryset, tablename):
        self.queryset = queryset
        self.tablename = tablename

    def count(self):
        cursor = connection.cursor()
        cursor.execute("SELECT reltuples FROM pg_class WHERE relname = %s", [self.tablename])
        row = cursor.fetchone()
        count = int(row[0])
        cursor.close()
        return count

    # passthrough all the other methods
    def __getattr__(self, attr):
        try:
            return object.__getattr__(self, attr)
        except AttributeError:
            return getattr(self.queryset, attr)
    
    def __getitem__(self, item):
         return self.queryset[item]

class MetadataCountQuerySet():
    def __init__(self, queryset, propertyname):
        self.queryset = queryset
        self.propertyname = propertyname

    def count(self):
        cursor = connection.cursor()
        cursor.execute("SELECT name_value FROM metadata WHERE name_type = %s", [self.propertyname])
        row = cursor.fetchone()
        count = int(row[0])
        cursor.close()
        return count

    # passthrough all the other methods
    def __getattr__(self, attr):
        try:
            return object.__getattr__(self, attr)
        except AttributeError:
            return getattr(self.queryset, attr)
            
    def __getitem__(self, key):
        return self.queryset[key]
        


def index(request):
    metadata = {}
    expired_certs = 0
    active_certs = 0
    total_certs = 0
    total_cas = 0
    
    messages = []
    if('subok' in request.GET):
        messages.append({'class':'alert-info','text':'<strong>Subscription request</strong> - We sent you a confirmation link via email. Click it, and you should be all set.'})
    if('unsubok' in request.GET):
        messages.append({'class':'alert-info','text':'<strong>Unsubscription request</strong> - We sent you a confirmation link via email. sClick it, and you should be all set.'})
    
    subscribeform = SubscribeUnsubscribeForm()
    
    with connection.cursor() as c:
        c.execute("SELECT NAME_TYPE, NAME_VALUE FROM metadata")
        rows = c.fetchall()
        for row in rows:
            metadata[row[0]] = row[1]

    return render(request, 'observer/index.html',
        {
            'total_certs': metadata['number_of_certs'],
            'total_ca': metadata['number_of_cas'],
            'total_logs': CtLog.objects.count(),
            'active_certs': metadata['number_of_active_certs'],
            'expired_certs': metadata['number_of_expired_certs'],
            'revoked_certs': metadata['number_of_revoked_certs'],
            'misissued_certs': metadata['number_of_misissued_certs'],
            'behaving_cas' : metadata['number_of_correctly_behaving_cas'],
            'interesting_cas' : metadata['number_of_interesting_cas'],
            'biggest_log' : metadata['number_of_certs_in_biggest_log'],
            'biggest_log_name' : CtLog.objects.get(id=metadata['biggest_log_id']).name,
            'smallest_log' : metadata['number_of_certs_in_smallest_log'],
            'uptime_days': (timezone.now().date()-datetime.date(2015,10,14)).days, #TODO
            'messages' : messages,
            'subscribeform' : subscribeform
        }
    )

def search(request):
    term = request.GET.get("term","")

    #found_ca = Ca.objects.filter(name__icontains=term)
    #found_cn_dnsname = Certificate.objects.raw("SELECT DISTINCT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, x509_notBefore(CERTIFICATE) FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE (NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) OR (NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s)))
    #ORDER BY x509_notBefore(CERTIFICATE) DESC", [term, term])

    return render(request, 'observer/search.html',
        {
            'term' : term
            #'found_ca' : found_ca,
            #'found_cn_dnsname' : found_cn_dnsname
        }
    )

def caall(request, page=None): #VIEW FOR CAs
    
    if(page==None):
        return HttpResponsePermanentRedirect("all/1")
    

    page = int(page)

    list_of_certs = []
    
    filtered_qs = CaFilter(
                      request.GET, 
                      queryset=Ca.objects.all().order_by('common_name')
                  )

    paginator = Paginator(filtered_qs.qs, ITEMS_PER_PAGE)
    page = request.GET.get('page')

    try:
        list_of_certs = paginator.page(page)
    except PageNotAnInteger:
        list_of_certs = paginator.page(1)
        
    return render(request, 'observer/cas.html',
        {
            'list_of_ca': list_of_certs, 
            'filter': filtered_qs#Ca.objects.annotate(num_certs=Count('certificate')).order_by('-num_certs'),
        }
    )

def certall(request, page=None, ae=None): #VIEW FOR Certificates->ALL

    if(page==None):
        return HttpResponsePermanentRedirect("all/1")

    ae = request.GET.get("algorithm")
    
        
    page = int(page)

    list_of_certs = []

    filtered_qs = CertFilter(
                      request.GET, 
                      queryset=FastCountQuerySet(Certificate.objects.all().order_by('-id'), 'certificate')
                  )
       

    paginator = Paginator(filtered_qs.qs, ITEMS_PER_PAGE)
    page = request.GET.get('page')

    try:
        list_of_certs = paginator.page(page)
    except PageNotAnInteger:
        list_of_certs = paginator.page(1)
        
    #if(ae != None):
        #list_of_certs = Certificate.objects.raw("SELECT * FROM certificate WHERE SIGNATURE_ALGORITHM=%s", [ae])
     
        
    return render(request, 'observer/certs.html',
        {
            'list_of_certs': list_of_certs, 
            'filter': filtered_qs
        }
    )

def certactive(request, page=None):

    if(page==None):
        return HttpResponsePermanentRedirect("active/1")

    page = int(page)

    list_of_certs = []

    paginator = Paginator(MetadataCountQuerySet(Certificate.objects.filter(not_before__lte=timezone.now(), not_after__gte=timezone.now()), 'number_of_active_certs'), ITEMS_PER_PAGE)
    if(page in paginator.page_range):
        list_of_certs = paginator.page(page)

    return render(request, 'observer/certs.html',
        {
            'list_of_certs': list_of_certs
        }
    )

def certexpired(request, page=None, order=None):
    if(page==None):
        return HttpResponsePermanentRedirect("expired/1")


    page = int(page)

    list_of_certs = []

    paginator = Paginator(MetadataCountQuerySet(Certificate.objects.filter(not_after__lt=timezone.now()), 'number_of_expired_certs'), ITEMS_PER_PAGE)
#    paginator = Paginator(Certificate.objects.filter(not_after__lt=timezone.now()), ITEMS_PER_PAGE)
    if(page in paginator.page_range):
        list_of_certs = paginator.page(page)

    return render(request, 'observer/certs.html',
        {
            'list_of_certs': list_of_certs
        }
    )
def certrevoked(request, page=None):
    if(page==None):
        return HttpResponsePermanentRedirect("revoked/1")

    page = int(page)

    list_of_certs = []

    paginator = Paginator(Certificate.objects.filter(id__in=RevokedCertificate.objects.all().values('certificate')), ITEMS_PER_PAGE)
    if(page in paginator.page_range):
        list_of_certs = paginator.page(page)

    return render(request, 'observer/certs.html',
        {
            'list_of_certs': list_of_certs
        }
    )

def certs_by_log(request, log_id, page=None):
    if(page==None):
        return HttpResponsePermanentRedirect("./1")

    page = int(page)
    log_id = int(log_id)
    
    list_of_certs = []
    
    paginator = Paginator(CtLogEntry.objects.filter(ct_log=log_id), ITEMS_PER_PAGE)
    if(page in paginator.page_range):
        list_of_entries = paginator.page(page)
        

    return render(request, 'observer/log_certs.html',
        {
            'log': get_object_or_404(CtLog, pk=log_id),
            'list_of_entries' : list_of_entries
        }
    )

def certs_by_ca(request, ca_id, page=None):

    if(page==None):
        return HttpResponsePermanentRedirect("certificates/1")

    page = int(page)
    ca_id = int(ca_id)

    list_of_certs = []
    
    
    
    filtered_qs = CertFilter(
                  request.GET, 
                  queryset=Certificate.objects.filter(issuer_ca=ca_id)
              )

    paginator = Paginator(filtered_qs.qs, ITEMS_PER_PAGE)
    page = request.GET.get('page')

    try:
        list_of_certs = paginator.page(page)
    except PageNotAnInteger:
        list_of_certs = paginator.page(1)
        
        
    return render(request, 'observer/certs.html',
        {
            'list_of_certs': list_of_certs, 
            'filter': filtered_qs
        })
    
    

#    paginator = Paginator(Certificate.objects.filter(issuer_ca=ca_id), ITEMS_PER_PAGE)
#    if(page in paginator.page_range):
#        list_of_certs = paginator.page(page)

#    return render(request, 'observer/certs.html',
#        {
#            'list_of_certs': list_of_certs
#        }
#    )

def list_cn_certs(request, cn):

    field_id = 'common name'
    expression = cn

    list_of_certs = Certificate.objects.raw("SELECT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, c.SERIAL, c.SHA256, c.NOT_BEFORE, c.NOT_AFTER FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE))=reverse(lower(%s)) ORDER BY c.NOT_BEFORE ASC", [cn])
    #list_of_certs = Certificate.objects.filter(certificate__common_name=cn).order_by('not_before')
    
    
    issues = issuefinder.get_all_issues(list(list_of_certs))
    #issues = issuefinder.get_first_certificates(list_of_certs)

    return render(request, 'observer/history.html',
        {
            'field_id': field_id,
            'expression': expression,
            'list_of_certs': list_of_certs,
            'issues':issues
        }
    )

def list_dnsname_certs(request, dnsname):

    field_id = 'dnsname'
    expression = dnsname

    list_of_certs = Certificate.objects.raw("SELECT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, c.SERIAL, c.SHA256, c.NOT_BEFORE, c.NOT_AFTER FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE))=reverse(lower(%s)) ORDER BY c.NOT_BEFORE ASC", [dnsname])
    
    issues = issuefinder.get_all_issues(list(list_of_certs))
    
    return render(request, 'observer/history.html',
        {
            'field_id': field_id,
            'expression': expression,
            'list_of_certs': list_of_certs,
            'issues':issues
        }
    )

def log(request): #LOG VIEW
    return render(request, 'observer/logs.html',
        {
            'list_of_logs': CtLog.objects.all().annotate(entries=Count('ctlogentry')).order_by('latest_entry_id')
            #'list_of_logs': CtLog.objects.all().order_by('-is_active','-latest_entry_id','name')
        }
    )

def cadetail(request,ca_id):
    ca = get_object_or_404(Ca, pk=ca_id)
    
    #counting number of issued CA's:
    number_of_issued_ca = Certificate.objects.filter(issuer_ca=ca_id).count()
    
    return render(request, 'observer/cadetail.html', { 'ca' : ca, 'number_of_issued_ca': number_of_issued_ca})


def certdetail(request,cert_id=None,cert_sha256=None):
    if cert_sha256:
        cert_sha256_bin = cert_sha256.decode('hex') #Does not work on python3
        cert = get_object_or_404(Certificate, certificate__sha256=cert_sha256_bin)
    if cert_id:
        cert = get_object_or_404(Certificate, pk=cert_id)
    cacert = CaCertificate.objects.filter(certificate_id=cert_id).first()
    digest_sha256 = str(cert.get_digest_sha256()).replace(':','').lower()[2:-1]

    #TODO
    #Certificate.objects.raw("select (select count(*) from certificate WHERE x509_keySize(certificate) = %s)*100/cast(COUNT(*) as float) as percentage, 0 as id FROM certificate;",
    #[cert.get_x509_data().get_pubkey().bits()])

    #return render(request, 'observer/certdetail.html', { 'certificate' : cert, 'ca_certificate' : cacert, 'keysize_distribution': round(keysize_distribution[0].percentage,2)})
    return render(request, 'observer/certdetail.html', { 'certificate' : cert, 'ca_certificate' : cacert, 'keysize_distribution': 'TODO', 'digest_sha256':digest_sha256})

def certraw(request,cert_id):
    cert = get_object_or_404(Certificate, pk=cert_id)
    
    response = HttpResponse(cert.certificate, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="certificate_{}.crt'.format(cert_id)
    return response

def logdetail(request,log_id):
    log = get_object_or_404(CtLog, pk=log_id)
    
    number_of_issued_ca = CtLogEntry.objects.filter(ct_log=log_id).count()
    return render(request, 'observer/logdetail.html', { 'log' : log, 'number_of_issued_ca' : number_of_issued_ca})

def flag(request, flag_id):
    try:
        with open(os.path.join(BASE_DIR, "static/flags/png/{0}.png".format(flag_id.lower())), "rb") as f:
            return HttpResponse(f.read(), content_type="image/png")
    except IOError:
        with open(os.path.join(BASE_DIR, "static/flags/png/-.png"), "rb") as f:
            return HttpResponse(f.read(), content_type="image/png")

def imprint(request):
    return render(request, 'observer/imprint.html')
    
def issues(request):
    return render(request, 'observer/issues.html')
    
def status(request):
    status = {'analyzer':{'lastrun':0}, 'monitor':{'lastrun':0}, 'msg':'ok'}
    try:
        with open('/static/data/status.json', 'r') as f:
            status = json.load(f)
            
        status['analyzer']['lastrun'] = datetime.datetime.fromtimestamp(status['analyzer']['lastrun'])
        status['monitor']['lastrun'] = datetime.datetime.fromtimestamp(status['monitor']['lastrun'])
    except Exception as e:
        status['msg'] = "Could not load status file."+str(e)
        
        
    return render(request, 'observer/status.html', {'status':status})


def certcheck(request):
    
    if request.method == 'POST':
        
        flag = request.POST['serial']
    
        data = '2582852852FF'
    
        sqlQuery = """SELECT id FROM certificate WHERE serial=%s"""
        sqlQuery_commonName = """SELECT * FROM ca WHERE """
        
        
        current_time = str(datetime.datetime.now())
            
        serial_int = int(data, 16)
        serial = serial_int.to_bytes((serial_int.bit_length() + 15) // 8, 'big', signed=True) or b'\0'
        sqlData = (psycopg2.Binary(serial),)
        
        found_serial = Certificate.objects.raw(sqlQuery, sqlData)
        
        if(found_serial):
            return HttpResponse(flag)
        

    return render(request, 'observer/checkserial.html', {})
