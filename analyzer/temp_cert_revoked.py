#! /usr/bin/env python2


import psycopg2
from OpenSSL import crypto
import re

db = psycopg2.connect("dbname='certwatch' user='postgres' host='localhost'")


cursor = db.cursor()
cursor.execute("SELECT c.certificate FROM ca_certificate cac inner join certificate c on cac.certificate_id = c.id")
for i in range(100):
    cert = cursor.fetchone()
    decoded_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert[0]))
    for e_idx in range(0, decoded_x509.get_extension_count()):
        extension = decoded_x509.get_extension(e_idx)
        short_name = extension.get_short_name()
        #print(short_name)
        if(short_name == "crlDistributionPoints"):
            for line in str(extension).split("\n"):
                m = re.search('URI:(.+)$',line)
                if m: 
                    print("crl", m.group(1))
        if(short_name == "authorityInfoAccess"):
            for line in str(extension).split("\n"):
#                print(line)
                m = re.search('OCSP - URI:(.+)$',line)
                if m: 
                    print("ocsp", m.group(1))
                    #https://tools.ietf.org/html/rfc6960#section-4.1