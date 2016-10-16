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
from notifier import Notifier

parser = argparse.ArgumentParser(prog='ct-analyzer')

parser.add_argument('-e', help='enable elasticsearch import', action='store_true')
parser.add_argument('-x', help='update expired certs', action='store_true')
parser.add_argument('-r', help='update revoked certs', action='store_true')
parser.add_argument('-m', help='update metadata certs', action='store_true')
parser.add_argument('-n', help='notify people that registered for updates', action='store_true')
parser.add_argument('-d', help='activate debug log output', action='store_true')
parser.add_argument('-g', help='update diagram data', action='store_true')
parser.add_argument('--force-replace', help='fetch the diagram data completely from the database instead of updating the existing values', action='store_true')
parser.add_argument('--t', help='time interval between refresh in minutes')
parser.add_argument('--pg', help='postgres database ip (default localhost)')
parser.add_argument('--es', help='elasticsearch database ip (default localhost)')
parser.add_argument('--web', help='web server ip (default localhost)')
parser.add_argument('--log', help='name of the file the log shall be written to')
parser.add_argument('--disable-tls-security', help='trust any TLS certificate (use only for testing purposes on localhost with self-signed certificate!)', action='store_true')
args = parser.parse_args()

host_db = args.pg if args.pg else "localhost"
host_es = args.es if args.es else "localhost"
host_web = args.web if args.web else "localhost"
interval = int(args.t)*60 if args.t else 180*60
logger = logging.getLogger(__name__)


# Thread structure:
# 
# Main
# |-> elasticsearch
# |-> diagram data
# |-> notify
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
    print("This is ctanalyzer.")
    
    logging_filename = args.log if args.log else None
    logging_level = logging.DEBUG if args.d else logging.INFO
    logging.basicConfig(level=logging_level, filename=logging_filename)
    
    logging.info("Date: {}".format(datetime.now()))
    
    RXMthread = None
    ESIthread = None
    DDthread = None
    INthread = None
    
    try:

        RXMthread = RXMwrapper('certwatch', 'postgres', host_db, args.r, args.x, args.m)
        RXMthread.start() # if none of r, u and m are true, nothing happens.
        
        if args.e:
            ESIthread = ESInserter('certwatch', 'postgres', host_db, host_es)
            ESIthread.start()
            
        if args.g:
            DDthread = Diagramdata('https://'+host_web, '/data', 'certwatch', 'postgres', host_db, disable_tls_security=args.disable_tls_security, force_replace=args.force_replace)
            DDthread.start()
        
        if args.n:
            Nthread = Notifier('certwatch', 'postgres', host_db)
            Nthread.start()
        
        
        logging.debug("Waiting for all running threads to terminate")
        
        logging.debug("JOINING RXMthread")
        RXMthread.join()
        
        if args.e:
            logging.debug("joining ESIthread")
            ESIthread.join()
            logging.debug("joined ESIthread")
            
        if args.g:
            logging.debug("joining DDthread")
            DDthread.join()
            logging.debug("joined DDthread")
            
        if args.n:
            logging.debug("joining Nthread")
            Nthread.join()
            logging.debug("joined Nthread")

    except Exception, e:
        logging.debug("EXCEPTION PANIC")
        logging.exception(e)
    
    print("Sleeping for {0} seconds".format(interval))
    logging.info("Sleeping for {0} seconds".format(interval))
    time.sleep(interval)
