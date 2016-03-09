import sys
import psycopg2
import argparse
import os
from datetime import datetime
from metadata import Metadata
from revokedcertificateanalyzer import RevokedCertificateAnalyzer
from dbtransformer import DBTransformer
from esinserter import ESInserter

host_db = "localhost"
host_es = "localhost"

parser = argparse.ArgumentParser(prog='ct-analyzer')
parser.add_argument('-e', help='enable elasticsearch import', action='store_true')
#parser.add_argument('-u', help='update expired certs', action='store_true')
parser.add_argument('-r', help='update revoked certs', action='store_true')
parser.add_argument('-m', help='update metadata certs', action='store_true')
parser.add_argument('--pg', help='postgres database ip (default localhost)')
parser.add_argument('--es', help='postgres database ip (default localhost)')
args = parser.parse_args()

host_db = args.pg if args.pg else os.getenv("POSTGRESHOST", "127.0.0.1")
host_es = args.es if args.es else "localhost"

#try:
db = psycopg2.connect("dbname='certwatch' user='postgres' host='"+host_db+"'")
print "{{ 'date':{}, 'data':{{".format(datetime.now())
#if args.u:
#    DBTransformer(db).update_expired_flag()
if args.r:
    RevokedCertificateAnalyzer(db).refresh_crls()
if args.m:
    Metadata(db).update_metadata()
if args.e:
    ESInserter(db,host_es).update_database()
print("}}")
db.close()
#except:
#    raise Exception("Couldn't connect to database")
