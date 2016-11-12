import psycopg2
import re
import urllib2
from OpenSSL import crypto
import logging
import Queue
import threading
import time
import ldapurl, ldap


class RevocationDetector(threading.Thread):
    def __init__(self,  dbname, dbuser, dbhost):
        threading.Thread.__init__(self)
        self.revoke_counter = 0
        self.found_in_database_counter = 0
        self.updated_counter = 0
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.db = None
        self.logger = logging.getLogger(__name__)
        
    def run(self):
        self.db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
        self.refresh_crls()
        self.db.close()
        
    def refresh_crls(self):
        running_download_threads = 1
        output_queue = Queue.Queue()
        log_queue = Queue.Queue()
        semaphore = threading.Semaphore(20) # number of concurrent download threads
        for crl_url in self.get_crl_urls_out_of_certificate_extensions():
            self.logger.debug("waiting for relase on semaphore")
            semaphore.acquire(blocking=True)
            self.logger.debug("retrieving and parsing {0}".format(crl_url))
            t = CrlDownloadThread(crl_url, output_queue, semaphore, log_queue, self.logger)
            t.start()
        while(running_download_threads > 0 or not output_queue.empty()):
            self.logger.debug("fetching crl from queue, {0} active threads".format(threading.active_count()))
                
            try:
                crl, crlraw = output_queue.get(block=True, timeout=10)
                self.logger.debug("parsing crl")
                self.parse_crl(crlraw)
            except Queue.Empty:
                self.logger.debug("Queue was empty, {0} active threads".format(threading.active_count()))
                running_download_threads = 0
                for thread in threading.enumerate():
                    if isinstance(thread, CrlDownloadThread): 
                        running_download_threads += 1
                        self.logger.debug("Running thread working on {0}".format(thread.getCrl()))
                self.logger.debug("------")
            except Exception as e:
                self.logger.exception("Exception: {0}".format(str(e)))
                log_queue.put((crl, "Exception when parsing: {0}".format(str(e))))
        self.logger.info("RevocationDetector done")
        with open("log.tsv", "w") as f:
            while(not log_queue.empty()):
                crl, val = log_queue.get(block=True)
                f.write("{}\t{}\n".format(crl, val))
            
        self.logger.info(self.print_log())

    #def download_and_parse_crl(self, url):
        #try:
            #crlraw = urllib2.urlopen(url).read()
            #self.parse_crl(crlraw)
        #except Exception as e:
            #pass

    def get_urls_from_certificate(self, certificate):
        urls = {'crl':[], 'ocsp':[]}
        for e_idx in range(0, certificate.get_extension_count()):
            extension = certificate.get_extension(e_idx)
            short_name = extension.get_short_name()
            if(short_name == "crlDistributionPoints"):
                for line in str(extension).split("\n"):
                    m = re.search('URI:(.+)$',line)
                    if m: 
                        url = m.group(1)
                        self.logger.debug("found crl url: {0}".format(url))
                        urls['crl'].append(url)
            if(short_name == "authorityInfoAccess"):
                for line in str(extension).split("\n"):
                    m = re.search('OCSP - URI:(.+)$',line)
                    if m: 
                        url = m.group(1)
                        self.logger.debug("found ocsp url: {0}".format(url))
                        urls['ocsp'].append(url) 
                        # we probably need to include data about the certificate
        return urls

    def get_crl_urls_out_of_certificate_extensions(self):
        crl_urls = []
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT c.certificate FROM ca_certificate cac inner join certificate c on cac.certificate_id = c.id")
        for cert in cursor.fetchall():
            decoded_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert[0]))
            urls = self.get_urls_from_certificate(decoded_x509)
            for crlurl in urls['crl']: 
                crl_urls.append(crlurl)
        return set(crl_urls)

    def parse_crl(self, crlraw):
        revoked_certs = crypto.load_crl(crypto.FILETYPE_ASN1, crlraw).get_revoked()
        if revoked_certs != None:
            self.analyze_revoked_certificates(revoked_certs)
        return

    def analyze_revoked_certificates(self, certificates):
        cursor = self.db.cursor()
        for certificate in certificates:
            self.revoke_counter += 1
            cursor.execute(
                "SELECT c.id, (rc is null) as isNotLogged  from certificate c LEFT OUTER JOIN revoked_certificate rc on rc.certificate_id = c.id WHERE c.SERIAL = %s",
                ("\\x" + certificate.get_serial(),))
            if cursor.rowcount > 0:
                self.found_in_database_counter += 1
                certificate_with_identic_serial = cursor.fetchone()
                if certificate_with_identic_serial[1]:
                    self.updated_counter += 1
                    cursor.execute("INSERT INTO revoked_certificate (certificate_id, date, reason) VALUES (%s,%s,%s)", (
                    certificate_with_identic_serial[0], str(certificate.get_rev_date())[:8],
                    str(certificate.get_reason())))
        self.db.commit()

    def print_log(self):
        return "{{'type':'revokedcerts','data':{{'found':{},'knew':{},'updated':{} }} }},".format(self.revoke_counter,self.found_in_database_counter,self.updated_counter)

class CrlDownloadThread(threading.Thread):
    def __init__(self, crl, output_queue, semaphore, log_queue, logger):
        threading.Thread.__init__(self)
        self.crl = crl
        self.output_queue = output_queue
        self.semaphore = semaphore
        self.log_queue = log_queue
        self.logger = logger
    
    def getCrl(self):
        return self.crl
    
    def run(self):
        start = time.time()
        self.logger.debug("starting thread to download {0}".format(self.crl))
        try:
            crlraw = None
            end = 0 # should be ok as a starting value, since it's 2016
            # LDAP
            if( ldapurl.isLDAPUrl( self.crl ) ):
                url_parts = ldapurl.LDAPUrl( self.crl )
                connectionstring = "{0}://{1}".format(url_parts.urlscheme, url_parts.hostport)
                
                try:
                    l = ldap.initialize(connectionstring)
                    try:
                        l.bind_s('','') #anonymous bind
                        scope = url_parts.scope if url_parts.scope != None else 0
                        if url_parts.filterstr == None:
                            res = l.search_s(url_parts.dn, scope, attrlist=url_parts.attrs)
                        else:
                            res = l.search_s(url_parts.dn, scope, url_parts.filterstr, attrlist=url_parts.attrs)
                        
                        for item in res:
                            for key in item[1]:
                                for crlraw in item[1][key]:
                                    self.output_queue.put((self.crl, crlraw))
                                    end = time.time()
                                    self.logger.debug("downloading {0} finished, took {1} seconds".format(self.crl, (end - start)))
                                    self.log_queue.put((self.crl, (end-start)))
                    except ldap.LDAPError, e:
                            if type(e.message) == dict:
                                for (k, v) in e.message.iteritems():
                                    self.logger.warn("%s: %s" % (k, v) )
                            else:
                                self.logger.warn(e)
                            end = time.time()
                            self.log_queue.put((self.crl, "LDAPError: {1} (after {0} seconds)".format((end-start), e)))
                finally:
                    try:
                        l.unbind()
                    except Error:
                        pass
            # HTTP(S)
            else:
                crlraw = urllib2.urlopen(self.crl).read()
                self.output_queue.put((self.crl, crlraw))
                end = time.time()
                self.logger.debug("downloading {0} finished, took {1} seconds".format(self.crl, (end - start)))
                self.log_queue.put((self.crl, (end-start)))
            if(end - start > 30):
                self.logger.warn("{0} was hella slow, took {1} seconds".format(self.crl, (end - start)))
        except Exception as e:
            end = time.time()
            self.logger.warn("Exception when downloading {0}: {1}".format(self.crl, str(e)))
            self.log_queue.put((self.crl, "EXCEPTION {1} (after {0} seconds)".format((end-start), e)))
        finally:
            self.semaphore.release()
