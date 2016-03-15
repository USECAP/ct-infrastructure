from django.http import HttpResponse
from django.db.models import Count
from django.db import connection
from django.views.decorators.cache import cache_page
from django.core.paginator import Paginator
import json
import re

from .models import *

def searchdb(term):
    return HttpResponse(term)

def getcas(request):
    output = "["

    for ca in Ca.objects.annotate(certcount=Count('certificate')).all():
        output += u'{{"id": "{id}", "name":"{name}", "C":"{C}", "CN":"{CN}", "L":"{L}", "O":"{O}", "OU":"{OU}", "ST":"{ST}", "certcount": {certcount}, "parent": {parent}}},'.format(
            id=str(ca.id),
            name=ca.name.replace('"','\''),
            certcount=str(ca.certcount),
            parent=str(CaCertificate.objects.filter(ca_id=ca.id).exclude(certificate__issuer_ca_id=ca.id).values_list('certificate__issuer_ca_id', flat=True)),
            C=ca.get_name_C(),
            CN=ca.get_name_CN().replace('"','\''),
            L=ca.get_name_L().replace('"','\''),
            O=ca.get_name_O().replace('"','\''),
            OU=ca.get_name_OU().replace('"','\''),
            ST=ca.get_name_ST().replace('"','\''))

    return HttpResponse(output[:-1]+"]")

def get_ca_info(request,id):
    children = []
    for child_ca_cert in CaCertificate.objects.filter(certificate__issuer_ca_id=id).exclude(ca_id=id) :
        children.append({"id": child_ca_cert.ca_id,"name":child_ca_cert.ca.get_name_CN(), "children": len(CaCertificate.objects.filter(certificate__issuer_ca_id=child_ca_cert.ca_id).exclude(ca_id=child_ca_cert.ca_id))})
    print(str(children))
    return HttpResponse(json.dumps({"id":id, "name":Ca.objects.get(id=id).get_name_CN(), "children": list(children)}))

def get_certificate_chain(request,cert_id):
    cert_id = int(cert_id)
    children = 0
    visited = []

    certificate = Certificate.objects.filter(id=cert_id).first()
    ca_of_certificate = certificate.issuer_ca_id

    name = certificate.subject_common_name()
    if(name == None):
        name = "[CN_empty]"
    children = {"id":cert_id, "name":name, "children":children}
    visited.append(cert_id)

    ca_certificate = CaCertificate.objects.filter(ca_id=ca_of_certificate).first()
    certificate_of_ca = ca_certificate.certificate_id

    iteration = 0
    while (certificate_of_ca not in visited) and (iteration < 1000):
        iteration += 1

        certificate = Certificate.objects.filter(id=certificate_of_ca).first()
        ca_of_certificate = certificate.issuer_ca_id

        name = certificate.subject_common_name()
        if(name == None):
            name = "[CN_empty]"
        children = {"id":certificate_of_ca, "name":name, "children":[children]}
        visited.append(certificate_of_ca)

        ca_certificate = CaCertificate.objects.filter(ca_id=ca_of_certificate).first()
        certificate_of_ca = ca_certificate.certificate_id

    return HttpResponse(json.dumps(children))

def get_ca_chain(request, ca_id):
    ca_id = int(ca_id)
    childrencount = Certificate.objects.filter(issuer_ca_id=ca_id).count()
    children = {"id":"number_of_children", "name":"{0} child certificates".format(childrencount), "children":0}
    visited = []

    Certificate.objects.filter(issuer_ca_id=ca_id).count()

    ca_certificate = CaCertificate.objects.filter(ca_id=ca_id).first()
    certificate_of_ca = ca_certificate.certificate_id

    iteration = 0
    while (certificate_of_ca not in visited) and (iteration < 1000):
        iteration += 1

        certificate = Certificate.objects.filter(id=certificate_of_ca).first()
        ca_of_certificate = certificate.issuer_ca_id

        name = certificate.subject_common_name()
        if(name == None):
            name = "[CN_empty]"
        children = {"id":certificate_of_ca, "name":name, "children":[children]}
        visited.append(certificate_of_ca)

        ca_certificate = CaCertificate.objects.filter(ca_id=ca_of_certificate).first()
        certificate_of_ca = ca_certificate.certificate_id

    return HttpResponse(json.dumps(children))

def getcaspage(request, page):
    ITEMS_PER_PAGE = 50
    page = int(page)

    paginator = Paginator(Ca.objects.annotate(certcount=Count('certificate')).all(), ITEMS_PER_PAGE)
    output = "["

    if(page not in paginator.page_range):
        return HttpResponse("[{}]")

    for ca in paginator.page(page):
        output += u'{{"id": "{id}", "name":"{name}", "C":"{C}", "CN":"{CN}", "L":"{L}", "O":"{O}", "OU":"{OU}", "ST":"{ST}", "certcount": {certcount}, "parent": {parent}}},'.format(
            id=str(ca.id),
            name=ca.name.replace('"','\''),
            certcount=str(ca.certcount), parent=str(CaCertificate.objects.filter(ca_id=ca.id).exclude(certificate__issuer_ca_id=ca.id).values_list('certificate__issuer_ca_id', flat=True)),
            C=ca.get_name_C(),
            CN=ca.get_name_CN().replace('"','\''),
            L=ca.get_name_L().replace('"','\''),
            O=ca.get_name_O().replace('"','\''),
            OU=ca.get_name_OU().replace('"','\''),
            ST=ca.get_name_ST().replace('"','\''))

    return HttpResponse(output[:-1]+"]")

@cache_page(60*60*24)
def get_cert_distribution_per_year(request):
    with connection.cursor() as c:
        result = []

        c.execute("select to_char(min(x509_notBefore(certificate)),'YYYY') as min, to_char(max(x509_notAfter(certificate)),'YYYY') as max from certificate;")
        cresult = c.fetchall()[0]

        for i in range(int(cresult[0]),int(cresult[1])+1):
            c.execute("select x509_keySize(certificate), count(*) from certificate where x509_notAfter(certificate) > '{}-01-01' and x509_notBefore(certificate) < '{}-01-01' group by x509_keySize(certificate) ".format(i,i+1))
            key_sizes = []
            active_certs = 0
            for entry in c.fetchall():
                key_sizes.append({'keySize': entry[0], 'count':entry[1]})
                active_certs += entry[1]

            c.execute("select x509_notAfter(certificate)-x509_notBefore(certificate), count(*) from certificate where x509_notAfter(certificate) > '{}-01-01' and x509_notBefore(certificate) < '{}-01-01' group by x509_notAfter(certificate)-x509_notBefore(certificate) ".format(i,i+1))
            durations = []
            for entry in c.fetchall():
                durations.append({'duration': entry[0], 'count':entry[1]})
            result.append({'year':i, 'active': active_certs, 'keySizes': key_sizes, 'durations': durations})

        print result
        return HttpResponse(json.dumps(result))


@cache_page(60*60*24)
def get_active_keysize_distribution(request, ca_id=None):
    with connection.cursor() as c:
        if(ca_id == None):
            command = "SELECT x509_keyAlgorithm(certificate) AS keyalgorithm, x509_keySize(certificate) AS keysize, count(*) AS count FROM certificate WHERE x509_notBefore(certificate) <  NOW() and x509_notAfter(certificate) > NOW() GROUP BY keysize, keyalgorithm ORDER BY count DESC;"
            c.execute(command)
        else:
            ca_id = int(ca_id)
            command = "SELECT x509_keyAlgorithm(certificate) AS keyalgorithm, x509_keySize(certificate) AS keysize, count(*) AS count FROM certificate WHERE issuer_ca_id=%s AND x509_notBefore(certificate) <  NOW() and x509_notAfter(certificate) > NOW() GROUP BY keysize, keyalgorithm ORDER BY count DESC;"
            c.execute(command, [ca_id])
        
        result = []
        other = 0
        row_nr = 0
        for row in c.fetchall():
            if(row_nr < 5):
                entry = {}
                entry['key'] = "{0}-{1}".format(row[0], row[1])
                entry['values'] = [{"value":row[2]}]
                result.append(entry)
            else:
                other += int(row[2])
            row_nr += 1
        if(other > 0):
            result.append({"key":"other", "values":[{"value":other}]})
            
        return HttpResponse(json.dumps(result))

@cache_page(60*60*24)
def get_signature_algorithm_distribution(request, ca_id=None):
    
    group_1 = []
    group_2 = []
    group_3 = []
    months = []
    algorithms = []
    
    with connection.cursor() as c:
        if(ca_id == None):
            command = "SELECT date_trunc('month', x509_notBefore(certificate)) AS month, x509_signatureHashAlgorithm(certificate) AS signaturehashalgorithm, x509_signatureKeyAlgorithm(certificate) AS signaturekeyalgorithm, count(*) AS count FROM certificate GROUP BY month, signaturehashalgorithm, signaturekeyalgorithm ORDER BY month ASC;"
            c.execute(command)
        else:
            ca_id = int(ca_id)
            command = "SELECT date_trunc('month', x509_notBefore(certificate)) AS month, x509_signatureHashAlgorithm(certificate) AS signaturehashalgorithm, x509_signatureKeyAlgorithm(certificate) AS signaturekeyalgorithm, count(*) AS count FROM certificate WHERE issuer_ca_id = %s GROUP BY month, signaturehashalgorithm, signaturekeyalgorithm ORDER BY month ASC;"
            c.execute(command, [ca_id])
        
        table = {}
        for row in c.fetchall():
            month = row[0].strftime("%Y-%m")
            if month not in table:
                table[month] = []
            table[month].append({"signaturealgorithm" : "{0}-{1}".format(row[1], row[2]), "count" : row[3]})
            
        for month in table:
            # sort algorithms in descending order
            sortedlist = sorted(table[month], key=lambda k: k['count'], reverse=True)
            if(len(sortedlist) > 0):
                if(sortedlist[0]["signaturealgorithm"] not in group_1):
                    group_1.append(sortedlist[0]["signaturealgorithm"])
            if(len(sortedlist) > 1):
                if(sortedlist[1]["signaturealgorithm"] not in group_2):
                    group_2.append(sortedlist[1]["signaturealgorithm"])
            if(len(sortedlist) > 2):
                if(sortedlist[2]["signaturealgorithm"] not in group_3):
                    group_3.append(sortedlist[2]["signaturealgorithm"])
            
        # fill algorithms filter with at least 3 signature algorithms
        algorithms = group_1[:]
        
        for g in group_2:
            if(len(algorithms) < 3):
                if(g not in algorithms):
                    algorithms.append(g)
        for g in group_3:
            if(len(algorithms) < 3):
                if(g not in algorithms):
                    algorithms.append(g)
        
        result = []
        
        for algo in algorithms:
            values = []
            for month in sorted(table):
                value = 0
                for localalgorithm in table[month]:
                    if(localalgorithm["signaturealgorithm"] == algo):
                        value = localalgorithm["count"]
                values.append([month, value])
            result.append({"key" : algo, "values" : values})
            
        return HttpResponse(json.dumps(result))

@cache_page(60*60*24)
def get_all_cert_information(request):
    return HttpResponse(json.dumps(
        {
            'active_certs': Certificate.objects.get_active().count(),
            'expired_certs': Certificate.objects.get_expired().count(),
            'revoked_certs': Certificate.objects.get_revoked().count()
        }
    ))

@cache_page(60*60*24)
def get_log_appearance_distribution(request):
    with connection.cursor() as c:
        c.execute("SELECT certs_in_logs.NUMBER_OF_LOGS, COUNT(*) AS CERTS_IN_X_LOGS FROM (SELECT CERTIFICATE_ID, COUNT(*) AS NUMBER_OF_LOGS FROM ct_log_entry GROUP BY CERTIFICATE_ID) AS certs_in_logs GROUP BY NUMBER_OF_LOGS ORDER BY CERTS_IN_X_LOGS;")

        result = []
        for entry in c.fetchall():
            result.append({"logs": str(entry[0]), "certificates": entry[1]})
        return HttpResponse(json.dumps(result))

@cache_page(60*60*24)
def get_log_information(request):
    colors = ["#1f77b4","#aec7e8","#ff7f0e","#ffbb78","#2ca02c","#98df8a","#d62728","#ff9896","#9467bd","#c5b0d5","#8c564b","#c49c94","#e377c2","#f7b6d2","#7f7f7f"] # https://github.com/mbostock/d3/wiki/Ordinal-Scales
    i = 0
    result = []
    for entry in CtLog.objects.annotate(entries=Count('ctlogentry')).order_by('-entries'):
        result.append({"id": entry.id, "key": entry.name, "values": [{"label": "Certificates","value":entry.entries}], "color": colors[i]})
        i += 1
    return HttpResponse(json.dumps({"unique_certificates": Certificate.objects.count(), "data": result}))

def search_cn_dnsname(request, term, offset):
    limit = 50
    result = {"limit":limit, "values":[]}
    has_more_data = False
    offset = int(offset)
    found_cn_dnsname = Certificate.objects.raw("SELECT DISTINCT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, x509_notBefore(CERTIFICATE) AS notBefore FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE (NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) OR (NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) ORDER BY notBefore DESC LIMIT %s OFFSET %s", [term, term, (limit+1), offset])
    
    counter = 0
    for cert in found_cn_dnsname:
        if(counter < limit):
            status = "<b>active</b>"
            if(cert.has_expired()):
                status = "expired"
            result["values"].append({
                "cert_id":cert.id,
                "cert_cn":cert.subject_common_name(),
                "ca_id":cert.issuer_ca.id,
                "ca_cn":cert.issuer_ca.get_name_CN(),
                "cert_not_before":cert.not_before(),
                "cert_status":status,
                "cert_not_after":cert.not_after()
            })
        else:
            has_more_data = True
        counter += 1
    
    result['has_more_data'] = has_more_data
    
    return HttpResponse(json.dumps(result))