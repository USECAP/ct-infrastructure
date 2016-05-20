#! /usr/bin/env python2

import sys
import psycopg2
import argparse
import os
import time
from datetime import datetime
import logging

from notifier import Notifier
from metadata import Metadata
from revokedcertificateanalyzer import RevokedCertificateAnalyzer
from dbtransformer import DBTransformer
from esinserter import ESInserter
from diagramdata import Diagramdata

parser = argparse.ArgumentParser(prog='ct-analyzer')

parser.add_argument('-l', help='log stuff', action='store_true')
parser.add_argument('-e', help='enable elasticsearch import', action='store_true')
parser.add_argument('-u', help='update expired certs', action='store_true')
parser.add_argument('-r', help='update revoked certs', action='store_true')
parser.add_argument('-m', help='update metadata certs', action='store_true')
parser.add_argument('-n', help='notify people that registered for updates', action='store_true')
parser.add_argument('-d', help='debug output', action='store_true')
parser.add_argument('-g', help='update diagram data', action='store_true')
parser.add_argument('--t', help='time interval between refresh in minutes')
parser.add_argument('--pg', help='postgres database ip (default localhost)')
parser.add_argument('--es', help='elasticsearch database ip (default localhost)')
parser.add_argument('--web', help='web server ip (default localhost)')
args = parser.parse_args()

host_db = args.pg if args.pg else "localhost"
host_es = args.es if args.es else "localhost"
host_web = args.web if args.web else "localhost"
interval = int(args.t)*60 if args.t else 180*60
#
while True:
    log = ""
    print("hallo")
    if args.d:
        logging.basicConfig(level=logging.DEBUG)
    try:
        db = psycopg2.connect("dbname='certwatch' user='postgres' host='"+host_db+"'")
        log += "{{ 'date':{}, 'data':{{".format(datetime.now())
        if args.u:
            log += DBTransformer(db).update_expired_flag()
            print("u", log)
        if args.r:
            log += RevokedCertificateAnalyzer(db).refresh_crls()
            print("r", log)
        if args.m:
            log += Metadata(db).update_metadata()
            print("m", log)
        if args.e:
            log += ESInserter(db,host_es).update_database()
            print("e", log)
        if args.g:
            log += Diagramdata('https://'+host_web,'/data',debug=args.d).update_diagrams()
            print("g", log)
        if args.n:
            log += Notifier(db).notify()
            print("n", log)
        log += "}}"
        db.close()
    except Exception, e:
        print(e)
        log += "{{ 'date':{}, 'error':'{}' }}".format(datetime.now(), e.message)

    if(args.l):
        f = open("log.txt","a")
        f.write("{}\n".format(log))
        f.close()

    time.sleep(interval)
