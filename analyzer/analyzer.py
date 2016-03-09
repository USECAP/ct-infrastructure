import sys
import psycopg2
import argparse
import os
import time
from datetime import datetime
from metadata import Metadata
from revokedcertificateanalyzer import RevokedCertificateAnalyzer
from dbtransformer import DBTransformer
from esinserter import ESInserter

parser = argparse.ArgumentParser(prog='ct-analyzer')

parser.add_argument('-e', help='enable elasticsearch import', action='store_true')
parser.add_argument('-u', help='update expired certs', action='store_true')
parser.add_argument('-r', help='update revoked certs', action='store_true')
parser.add_argument('-m', help='update metadata certs', action='store_true')
parser.add_argument('--t', help='time interval between refresh in minutes', action='store_true')
parser.add_argument('--pg', help='postgres database ip (default localhost)')
parser.add_argument('--es', help='elasticsearch database ip (default localhost)')
args = parser.parse_args()

host_db = args.pg if args.pg else "localhost"
host_es = args.es if args.es else "localhost"
interval = args.t*60 if args.t else 180*60
#
while True:
    try:
        db = psycopg2.connect("dbname='certwatch' user='postgres' host='"+host_db+"'")
        print "{{ 'date':{}, 'data':{{".format(datetime.now())
        if args.u:
            DBTransformer(db).update_expired_flag()
        if args.r:
            RevokedCertificateAnalyzer(db).refresh_crls()
        if args.m:
            Metadata(db).update_metadata()
        if args.e:
            ESInserter(db,host_es).update_database()
        print("}}")
        db.close()
    except:
        print "{{ 'date':{}, 'error':'true' }}".format(datetime.now())
    time.sleep(interval)    
