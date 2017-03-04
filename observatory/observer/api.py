from django.http import HttpResponse
from django.db.models import Count
from django.db import connection
from django.views.decorators.cache import cache_page
from django.core.paginator import Paginator
import json
import datetime
import logging

from .models import Ca, Certificate, CaCertificate, CtLog

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
            C=ca.country_name,
            CN=ca.common_name.replace('"','\''),
            L=ca.locality_name.replace('"','\''),
            O=ca.organization_name.replace('"','\''),
            OU=ca.organizational_unit_name.replace('"','\''),
            ST=ca.state_or_province_name.replace('"','\''))

    return HttpResponse(output[:-1]+"]")

def get_ca_info(request,id):
    children = []
    for child_ca_cert in CaCertificate.objects.filter(certificate__issuer_ca_id=id).exclude(ca_id=id) :
        children.append({"id": child_ca_cert.ca_id,"name":child_ca_cert.ca.common_name, "children": len(CaCertificate.objects.filter(certificate__issuer_ca_id=child_ca_cert.ca_id).exclude(ca_id=child_ca_cert.ca_id))})
    print(str(children))
    return HttpResponse(json.dumps({"id":id, "name":Ca.objects.get(id=id).common_name, "children": list(children)}))

def get_certificate_chain(request, cert_id):
    cert_id = int(cert_id)
    visited = []
    
    
    children = {"id":cert_id, "name":"", "children":0}

    try:
        certificate = Certificate.objects.get(id=cert_id)
        ca_of_certificate = certificate.issuer_ca
    
        name = certificate.subject_common_name()
        if(name == None):
            name = "[CN_empty]"
        children['name'] = name
        visited.append(cert_id)
    
        #ca_certificate = CaCertificate.objects.get(ca=ca_of_certificate)
        ca_certificate = CaCertificate.objects.filter(ca=ca_of_certificate).first()
        
        certificate_of_ca = ca_certificate.certificate_id
    
        iteration = 0
        while (certificate_of_ca not in visited) and (iteration < 1000):
            iteration += 1
    
            certificate = Certificate.objects.get(id=certificate_of_ca)
            ca_of_certificate = certificate.issuer_ca
            
    
            name = certificate.subject_common_name()
            if(name == None):
                name = "[CN_empty]"
            children = {"id":certificate_of_ca, "name":name, "children":[children]}
            visited.append(certificate_of_ca)
    
            #ca_certificate = CaCertificate.objects.get(ca_id=ca_of_certificate)
            ca_certificate = CaCertificate.objects.filter(ca_id=ca_of_certificate).first()
            certificate_of_ca = ca_certificate.certificate_id
            
        children['status'] = "OK"
    except (CaCertificate.DoesNotExist, Certificate.DoesNotExist):
        children['status'] = "ERROR"
        
    return HttpResponse(json.dumps(children))

def get_ca_chain(request, ca_id):
    ca_id = int(ca_id)
    childrencount = Certificate.objects.filter(issuer_ca=ca_id).count()
    children = {"id":"number_of_children", "name":"{0} child certificates".format(childrencount), "children":0}
    visited = []

    try:
        #ca_certificate = CaCertificate.objects.get(ca_id=ca_id)
        ca_certificate = CaCertificate.objects.filter(ca_id=ca_id).first()
        certificate_of_ca = ca_certificate.certificate_id
    
        iteration = 0
        while (certificate_of_ca not in visited) and (iteration < 1000):
            iteration += 1
    
            #certificate = Certificate.objects.get(id=certificate_of_ca)
            certificate = Certificate.objects.filter(id=certificate_of_ca).first()
            ca_of_certificate = certificate.issuer_ca
            
    
            name = certificate.subject_common_name()
            if(name == None):
                name = "[CN_empty]"
            children = {"id":certificate_of_ca, "name":name, "children":[children]}
            visited.append(certificate_of_ca)
    
            #ca_certificate = CaCertificate.objects.get(ca_id=ca_of_certificate)
            ca_certificate = CaCertificate.objects.filter(ca_id=ca_of_certificate).first()
            certificate_of_ca = ca_certificate.certificate_id

        children['status'] = "OK"    
    except (CaCertificate.DoesNotExist, Certificate.DoesNotExist):
        children['status'] = "ERROR"

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
            C=ca.country_name,
            CN=ca.common_name.replace('"','\''),
            L=ca.locality_name.replace('"','\''),
            O=ca.organization_name.replace('"','\''),
            OU=ca.organizational_unit_name.replace('"','\''),
            ST=ca.state_or_province_name.replace('"','\''))

    return HttpResponse(output[:-1]+"]")

@cache_page(60*50)
def get_cert_distribution_per_year(request):
    with connection.cursor() as c:
        result = []

        c.execute("select to_char(min(NOT_BEFORE),'YYYY') as min, to_char(max(NOT_AFTER),'YYYY') as max from certificate;")
        cresult = c.fetchall()[0]

        for i in range(int(cresult[0]),int(cresult[1])+1):
            c.execute("select KEY_SIZE, count(*) from certificate where NOT_AFTER > '{}-01-01' and NOT_BEFORE < '{}-01-01' group by KEY_SIZE".format(i,i+1))
            key_sizes = []
            active_certs = 0
            for entry in c.fetchall():
                key_sizes.append({'keySize': entry[0], 'count':entry[1]})
                active_certs += entry[1]

            c.execute("select NOT_AFTER - NOT_BEFORE, count(*) from certificate where NOT_AFTER > '{}-01-01' and NOT_BEFORE < '{}-01-01' group by NOT_AFTER - NOT_BEFORE ".format(i,i+1))
            durations = []
            for entry in c.fetchall():
                durations.append({'duration': entry[0], 'count':entry[1]})
            result.append({'year':i, 'active': active_certs, 'keySizes': key_sizes, 'durations': durations})

        return HttpResponse(json.dumps({'max_id':-1, 'data':result, 'aggregated':True}))


@cache_page(60*50)
def get_active_keysize_distribution(request, ca_id=None, id_from=None):
    max_id = None
    
    with connection.cursor() as c:
        
        c.execute("SELECT MAX(id) FROM certificate;")
        row = c.fetchone()
        max_id = int(row[0])
        
        aggregate = (id_from == None or int(id_from) < 1)
        result = None
        
        if(aggregate):
        
            if(ca_id == None):
                command = "SELECT KEY_ALGORITHM, KEY_SIZE, count(*) AS count FROM certificate WHERE id <= %s AND NOT_BEFORE <  NOW() and NOT_AFTER > NOW() GROUP BY KEY_SIZE, KEY_ALGORITHM ORDER BY count DESC;"
                c.execute(command, [max_id])
            else:
                ca_id = int(ca_id)
                command = "SELECT KEY_ALGORITHM, KEY_SIZE, count(*) AS count FROM certificate WHERE id <= %s AND issuer_ca_id=%s AND NOT_BEFORE <  NOW() and NOT_AFTER > NOW() GROUP BY KEY_SIZE, KEY_ALGORITHM ORDER BY count DESC;"
                c.execute(command, [max_id, ca_id])
            
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
        
        else:
            if(ca_id == None):
                command = "SELECT KEY_ALGORITHM, KEY_SIZE, count(*) AS count FROM certificate WHERE id > %s AND id <= %s AND NOT_BEFORE <  NOW() and NOT_AFTER > NOW() GROUP BY KEY_SIZE, KEY_ALGORITHM ORDER BY count DESC;"
                c.execute(command, [int(id_from), max_id])
            else:
                ca_id = int(ca_id)
                command = "SELECT KEY_ALGORITHM, KEY_SIZE, count(*) AS count FROM certificate WHERE id > %s AND id <= %s AND issuer_ca_id=%s AND NOT_BEFORE <  NOW() and NOT_AFTER > NOW() GROUP BY KEY_SIZE, KEY_ALGORITHM ORDER BY count DESC;"
                c.execute(command, [int(id_from), max_id, ca_id])
            
            result = {}
            other = 0
            row_nr = 0
            for row in c.fetchall():
                    key = "{0}-{1}".format(row[0], row[1])
                    value = row[2]
                    result[key] = value
            
        return HttpResponse(json.dumps({'max_id':max_id, 'data':result, 'aggregated':aggregate}))

@cache_page(60*50)
def get_signature_algorithm_distribution(request, ca_id=None, id_from=None):
    max_id = None
    
    algorithms = ["sha1WithRSAEncryption", "sha256WithRSAEncryption", "ecdsa-with-SHA256"]
    
    with connection.cursor() as c:
        
        c.execute("SELECT MAX(id) FROM certificate;")
        row = c.fetchone()
        max_id = int(row[0])
        
        aggregate = (id_from == None or int(id_from) < 1)
        result = None
        
        if(aggregate):

            if(ca_id == None):
                command = "SELECT date_trunc('month', NOT_BEFORE) AS month, SIGNATURE_ALGORITHM, count(*) AS count FROM certificate WHERE id <= %s GROUP BY month, SIGNATURE_ALGORITHM ORDER BY month ASC;"
                c.execute(command, [max_id])
            else:
                ca_id = int(ca_id)
                command = "SELECT date_trunc('month', NOT_BEFORE) AS month, SIGNATURE_ALGORITHM, count(*) AS count FROM certificate WHERE id <= %s AND issuer_ca_id = %s GROUP BY month, SIGNATURE_ALGORITHM ORDER BY month ASC;"
                c.execute(command, [max_id, ca_id])
            
            table = {}
            for row in c.fetchall():
                month = row[0].strftime("%Y-%m")
                if month not in table:
                    table[month] = []
                table[month].append({"signaturealgorithm" : row[1], "count" : row[2]})

            result = []
            
            # create entries for selected algorithms
            for algo in algorithms:
                values = []
                for month in sorted(table):
                    value = 0
                    for localalgorithm in table[month]:
                        if(localalgorithm["signaturealgorithm"] == algo):
                            value = localalgorithm["count"]
                    values.append([month, value])
                result.append({"key" : algo, "values" : values})
                
            # create entries for 'other'
            values = []
            for month in sorted(table):
                value = 0
                for localalgorithm in table[month]:
                    if(localalgorithm["signaturealgorithm"] not in algorithms):
                        value += localalgorithm["count"]
                values.append([month, value])
            result.append({"key" : 'other', "values" : values})
            
        else:
            
            if(ca_id == None):
                command = "SELECT date_trunc('month', NOT_BEFORE) AS month, SIGNATURE_ALGORITHM, count(*) AS count FROM certificate WHERE id > %s AND id <= %s GROUP BY month, SIGNATURE_ALGORITHM ORDER BY month ASC;"
                c.execute(command, [int(id_from), max_id])
            else:
                ca_id = int(ca_id)
                command = "SELECT date_trunc('month', NOT_BEFORE) AS month, SIGNATURE_ALGORITHM, count(*) AS count FROM certificate WHERE id > %s AND id <= %s AND issuer_ca_id = %s GROUP BY month, SIGNATURE_ALGORITHM ORDER BY month ASC;"
                c.execute(command, [int(id_from), max_id, ca_id])
            
            result = {}
            for row in c.fetchall():
                month = row[0].strftime("%Y-%m")
                algo = row[1]
                
                if algo not in result:
                    result[algo] = {}
                    
                if month not in result[algo]:
                    result[algo][month] = 0
                
                result[algo][month] += row[2]
                
            
        return HttpResponse(json.dumps({'max_id':max_id, 'data':result, 'aggregated':aggregate}))

@cache_page(60*50)
def get_ca_distribution(request, id_from=None):

    cas = []
    max_id = None
    
    with connection.cursor() as c:
        
        c.execute("SELECT MAX(id) FROM certificate;")
        row = c.fetchone()
        max_id = int(row[0])
        aggregate = (id_from == None or int(id_from) < 1)
        result = None
        
        if(aggregate):
            # return raw data formatted for the diagram
            # do statistics between 0 and max_id;
            # aggregate cas with less than 50000 under 'other'

            command = """SELECT date_trunc('month', NOT_BEFORE) AS month, 
                            crt.ISSUER_CA_ID, 
                            ca.ORGANIZATION_NAME, 
                            count(crt.ISSUER_CA_ID) AS count 
                        FROM certificate crt JOIN ca ON crt.ISSUER_CA_ID = ca.id 
                        WHERE crt.id <= %s 
                        GROUP BY month, 
                            crt.ISSUER_CA_ID, 
                            ca.ORGANIZATION_NAME 
                        ORDER BY month DESC""";
            c.execute(command, [max_id])
        
            table = {}
            for row in c.fetchall():
                month = row[0].strftime("%Y-%m")
                if month not in table:
                    table[month] = {}
                ca = row[2]
                if(ca not in table[month]):
                    table[month][ca] = 0
                table[month][ca] += row[3]
        
            for month in table:
                # sort cas in descending order
                for ca in table[month]:
                    if(table[month][ca] > 50000):
                        if(ca not in cas):
                            cas.append(ca)
        
            result = []
        
            for ca in cas:
                values = []
                for month in sorted(table):
                    value = 0
                    for localca in table[month]:
                        if(localca == ca):
                            value = table[month][localca]
                    values.append([month, value])
                
                result.append({"key" : ca, "values" : values})
        
            # now add up the other CAs
            values = []
            for month in sorted(table):
                value = 0
                for localca in table[month]:
                    if(localca not in cas):
                        value += table[month][localca]
                values.append([month, value])
            
            result.append({"key" : 'other', "values" : values})
            
        else:
            # return a dict with data updates
            # do statistics between id_from and max_id;
            # do not aggregate 'others' at the end

            command = "SELECT date_trunc('month', NOT_BEFORE) AS month, crt.ISSUER_CA_ID, ca.ORGANIZATION_NAME, count(crt.ISSUER_CA_ID) AS count FROM certificate crt JOIN ca ON crt.ISSUER_CA_ID = ca.id WHERE crt.id > %s AND crt.id <= %s GROUP BY month, crt.ISSUER_CA_ID, ca.ORGANIZATION_NAME ORDER BY month DESC;"
            c.execute(command, [int(id_from), max_id])
            
            table = {}
            for row in c.fetchall():
                month = row[0].strftime("%Y-%m")
                if month not in table:
                    table[month] = {}
                ca = row[2]
                if(ca not in table[month]):
                    table[month][ca] = 0
                table[month][ca] += row[3]
                cas.append(ca)
        
            result = {}
        
            for ca in cas:
                values = {}
                for month in sorted(table):
                    value = 0
                    for localca in table[month]:
                        if(localca == ca):
                            value = table[month][localca]
                    if(value > 0):
                        values[month] = value
                
                result[ca] = values

            
            
        return HttpResponse(json.dumps({'max_id':max_id, 'data':result, 'aggregated':aggregate}))

@cache_page(60*50)
def get_all_cert_information(request):
    return HttpResponse(json.dumps(
        {
            'active_certs': Certificate.objects.get_active().count(),
            'expired_certs': Certificate.objects.get_expired().count(),
            'revoked_certs': Certificate.objects.get_revoked().count()
        }
    ))

@cache_page(60*50)
def get_log_appearance_distribution(request):
    with connection.cursor() as c:
        c.execute("SELECT certs_in_logs.NUMBER_OF_LOGS, COUNT(*) AS CERTS_IN_X_LOGS FROM (SELECT CERTIFICATE_ID, COUNT(DISTINCT ct_log_id) AS NUMBER_OF_LOGS FROM ct_log_entry GROUP BY CERTIFICATE_ID) AS certs_in_logs GROUP BY NUMBER_OF_LOGS ORDER BY CERTS_IN_X_LOGS;")

        result = []
        for entry in c.fetchall():
            result.append({"logs": str(entry[0]), "certificates": entry[1]})
        return HttpResponse(json.dumps({'max_id':-1, 'data':result, 'aggregated':True}))

@cache_page(60*50)
def get_log_information(request):
    colors = ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c', '#98df8a', '#d62728', '#ff9896', '#9467bd', '#c5b0d5', '#8c564b', '#c49c94', '#e377c2', '#f7b6d2', '#7f7f7f', '#c7c7c7', '#bcbd22', '#dbdb8d', '#17becf', '#9edae5', '#393b79', '#5254a3', '#6b6ecf', '#9c9ede', '#637939', '#8ca252', '#b5cf6b', '#cedb9c', '#8c6d31', '#bd9e39', '#e7ba52', '#e7cb94', '#843c39', '#ad494a', '#d6616b', '#e7969c', '#7b4173', '#a55194', '#ce6dbd', '#de9ed6'] # https://github.com/d3/d3-3.x-api-reference/blob/master/Ordinal-Scales.md
    i = 0
    result = []
    for entry in CtLog.objects.exclude(latest_log_size__isnull=True).order_by('-latest_log_size'):
        
        fetched_percentage = "-"        
        if(entry.latest_log_size != None and entry.latest_entry_id != None):
            fetched_percentage = int((float(entry.latest_entry_id) / (entry.latest_log_size-1) * 100))
        
        result.append({"id": entry.id, "key": entry.name, "values": [{"label": "Certificates","value":entry.latest_log_size-1,"latest_entry_id":entry.latest_entry_id,"fetched_percentage":"{0} %".format(fetched_percentage)}], "color": colors[(i % len(colors))]})
        i += 1
    return HttpResponse(json.dumps({'max_id':-1, "unique_certificates": Certificate.objects.count(), "data": result, 'aggregated':True}))

def search_ca(request, term, offset=0):
    limit = 50
    result = {"limit":limit, "values":[]}
    has_more_data = False
    
    set_from = int(offset)
    set_to = set_from + limit + 1
    queryset = Ca.objects.filter(common_name__icontains=term)
    queryset |= Ca.objects.filter(state_or_province_name__icontains=term)
    queryset |= Ca.objects.filter(locality_name__icontains=term)
    queryset |= Ca.objects.filter(organization_name__icontains=term)
    queryset |= Ca.objects.filter(organizational_unit_name__icontains=term)
    queryset |= Ca.objects.filter(email_address__icontains=term)
    found_ca = queryset.order_by('id')[set_from:set_to]
    
    counter = 0
    for ca in found_ca:
        if(counter < limit):
            result["values"].append({
                "ca_id":ca.id,
                "c":ca.country_name,
                "cn":ca.common_name,
                "l":ca.locality_name,
                "o":ca.organization_name,
                "ou":ca.organizational_unit_name,
                "st":ca.state_or_province_name
            })
        else:
            has_more_data = True
        counter += 1
    
    result['has_more_data'] = has_more_data
    
    return HttpResponse(json.dumps(result))

def search_cn_dnsname(request, term, offset=0):
    limit = 50
    result = {"limit":limit, "values":[]}
    has_more_data = False
    offset = int(offset)
    found_cn_dnsname = Certificate.objects.raw("SELECT DISTINCT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, c.NOT_BEFORE FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE (NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) OR (NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) ORDER BY c.NOT_BEFORE DESC LIMIT %s OFFSET %s", [term, term, (limit+1), offset])
    
    counter = 0
    for cert in found_cn_dnsname:
        if(counter < limit):
            result["values"].append({
                "cert_id":cert.id,
                "cert_cn":cert.subject_common_name(),
                "ca_id":cert.issuer_ca.id,
                "ca_cn":cert.issuer_ca.common_name,
                "cert_not_before":cert.notbefore(),
                "cert_status":"expired" if (cert.not_after < datetime.datetime.now()) else "<b>active</b>",
                "cert_not_after":cert.notafter()
            })
        else:
            has_more_data = True
        counter += 1
    
    result['has_more_data'] = has_more_data
    
    return HttpResponse(json.dumps(result))

def search_certificate_by_fingerprint(request, fingerprint):
    if fingerprint:
        try:
            search_result = Certificate.objects.raw("SELECT * "
                                           "from certificate where x509_publickey(certificate) = '%s' "
                                           "OR x509_publickeymd5(certificate) = '%s'" % (fingerprint,fingerprint))[0]
            print(search_result)
            return HttpResponse(True)
        except:
            pass
    return HttpResponse(False)

def get_last_certificates_for_dnsname(request, term, limit=5):
    if limit > 20:
        limit = 20
    found_cn_dnsname = Certificate.objects.raw("SELECT DISTINCT c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, c.NOT_BEFORE FROM certificate_identity AS ci JOIN certificate AS c ON ci.CERTIFICATE_ID=c.ID WHERE (NAME_TYPE='dNSName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) OR (NAME_TYPE='commonName' AND reverse(lower(NAME_VALUE)) LIKE reverse(lower(%s))) ORDER BY NOT_BEFORE DESC LIMIT %s", [term, term, limit])
    print(term, limit, found_cn_dnsname)
    result = []
    for cert in found_cn_dnsname:
        result.append(
           {
                "cert_id":cert.id,
                "cert_cn":cert.subject_common_name(),
                "ca_id":cert.issuer_ca.id,
                "ca_cn":cert.issuer_ca.common_name,
                "cert_not_before":cert.notbefore(),
                "expired":cert.has_expired(),
                "cert_not_after":cert.notafter()
            }
        )
    return HttpResponse(json.dumps(result))