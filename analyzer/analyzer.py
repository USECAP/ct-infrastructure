#! /usr/bin/env python2

import sys
import psycopg2
import argparse
import os
import time
from datetime import datetime
import logging
import threading

from notifier import Notifier
from metadata import Metadata
from revocationdetector import RevocationDetector
from expirationdetector import ExpirationDetector
from esinserter import ESInserter
from diagramdata import Diagramdata
from issuefinder import IssueFinder

parser = argparse.ArgumentParser(prog='ct-analyzer')

parser.add_argument('-l', help='log stuff', action='store_true')
parser.add_argument('-e', help='enable elasticsearch import', action='store_true')
parser.add_argument('-x', help='update expired certs', action='store_true')
parser.add_argument('-r', help='update revoked certs', action='store_true')
parser.add_argument('-m', help='update metadata certs', action='store_true')
parser.add_argument('-n', help='notify people that registered for updates', action='store_true')
parser.add_argument('-d', help='debug output', action='store_true')
parser.add_argument('-g', help='update diagram data', action='store_true')
parser.add_argument('-i', help='identify issues', action='store_true')
parser.add_argument('--t', help='time interval between refresh in minutes')
parser.add_argument('--pg', help='postgres database ip (default localhost)')
parser.add_argument('--es', help='elasticsearch database ip (default localhost)')
parser.add_argument('--web', help='web server ip (default localhost)')
args = parser.parse_args()

host_db = args.pg if args.pg else "localhost"
host_es = args.es if args.es else "localhost"
host_web = args.web if args.web else "localhost"
interval = int(args.t)*60 if args.t else 180*60


# Thread structure:
# 
# Main
# |-> elasticsearch
# |-> diagram data
# |-> issues -> notify
# |-> | (RXMwrapper)
#     |-> revoked |
#     |-> expired |
#                 |-> metadata

 # ./analyzer.py --pg=ctdatabase --es=elasticsearch --web=ctobservatory -d

class RXMwrapper(threading.Thread):
    def __init__(self, dbname, dbuser, dbhost, do_revocation_detection, do_expiration_detection, do_metadata):
        threading.Thread.__init__(self)
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.do_revocation_detection = do_revocation_detection
        self.do_expiration_detection = do_expiration_detection
        self.do_metadata = do_metadata
        
    def run(self):
        RDthread = None
        EDthread = None
        if(self.do_revocation_detection):
            RDthread = RevocationDetector(self.dbname, self.dbuser, self.dbhost)
            RDthread.start()
         
        if(self.do_expiration_detection):
            EDthread = ExpirationDetector(self.dbname, self.dbuser, self.dbhost)
            EDthread.start()
            
        if(self.do_revocation_detection):
            RDthread.join()
         
        if(self.do_expiration_detection):
            EDthread.join()
            
        if(self.do_metadata):
            MDthread = Metadata(self.dbname, self.dbuser, self.dbhost)
            MDthread.start()
            MDthread.join()
            
        
         



while True:
    log = ""
    print("hallo")
    if args.d:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    try:
        db = psycopg2.connect("dbname='certwatch' user='postgres' host='"+host_db+"'")
        log += "{{ 'date':{}, 'data':{{".format(datetime.now())
        #if args.u:
            #log += DBTransformer(db).update_expired_flag()
            #print("u", log)
        #if args.r:
            #RDthread = RevokedCertificateAnalyzer(db)
            #RDthread.start()
            ##TODO logging
            #print("r", 'log')
        #if args.m:
            #log += Metadata(db).update_metadata()
            #print("m", log)
        RXMthread = RXMwrapper('certwatch', 'postgres', host_db, args.r, args.x, args.m)
        RXMthread.start() # if none of r, u and m are true, nothing happens.
        
        
        if args.e:
            ESIthread = ESInserter('certwatch', 'postgres', host_db, host_es)
            ESIthread.start()
            #TODO logging
            print("e", 'log')
        if args.g:
            DDthread = Diagramdata('https://'+host_web,'/data',debug=args.d)
            DDthread.start()
            print("g", 'log')
        if args.i:
            IFthread = IssueFinder('certwatch', 'postgres', host_db)
            IFthread.start()
            #TODO logging
            print("i", 'log')
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
