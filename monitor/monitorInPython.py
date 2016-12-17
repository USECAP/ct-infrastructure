import psycopg2
import requests
import base64
import OpenSSL
import sys
import logging
import argparse
import re
import binascii
import datetime
import queue
import threading
from dateutil import parser
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat




def connectToDatabase(name="certwatch", user="postgres", host="localhost"):
    database = _LocalDatabase(name, user, host)
    return database




def monitor(database):
    logging.debug("Retrieving new log entries")
    newLogEntries = database.retrieveNewLogEntries()
    logging.debug("Populating new log entries")
    database.populateNewLogEntries(newLogEntries)
    database.updateCtLogStats()





class _LocalDatabase:
    def __init__(self, name, user, host):
        self.name = name
        self.user = user
        self.host = host
        self.connectionToDataBase = self.establishConnectionToDatabase()
        self.cursor = self.connectionToDataBase.cursor()




    def establishConnectionToDatabase(self):
        try:
            dataBase = psycopg2.connect(dbname=self.name,
                                                user=self.user,
                                                host=self.host)
            return dataBase

        except:
            logging.error("Error connecting to local database")
            exit()




    def retrieveNewLogEntries(self):
        newLogEntriesQ = queue.Queue()
        threads = []
        activeLogServers = self.getActiveLogServers()

        for activeLogServer in activeLogServers:
            logging.debug("Querying {}...".format(activeLogServer.url))

            t = EntryFromLogserverRetrievalThread(self, activeLogServer, newLogEntriesQ)
            t.start()
            threads.append(t)

        # wait for all threads to finish (join order does not matter)
        for t in threads:
            t.join()
        
        # create a huge list from the elements in the queue
        newLogEntries = []
        while not newLogEntriesQ.empty():
            newLogEntries += newLogEntriesQ.get()
        
        return newLogEntries




    def getActiveLogServers(self):
        try:
            self.cursor.execute("""SELECT ID, URL, NAME, PUBLIC_KEY, LATEST_ENTRY_ID, 
            LATEST_UPDATE, OPERATOR, IS_ACTIVE, LATEST_STH_TIMESTAMP, MMD_IN_SECONDS 
            FROM ct_log as ctl 
            WHERE ctl.IS_ACTIVE""")
            activeLogServerEntries = self.cursor.fetchall()

        except:
            logging.error("Could not execute Active Log Server Entries Query. {}".format(sys.exc_info()[0]))
            exit()

        else:
            activeLogServers = []
            for activeLogServerEntry in activeLogServerEntries:
                activeLogServers.append(_LogServer(activeLogServerEntry))

            return activeLogServers





    def requestNewEntriesFromServer(self, logServerEntry):
        requestedEntries = []
        
        sthOfLogServer = self.requestSTHOfLogServer(logServerEntry)
        logging.debug("Log tree size: {}".format(sthOfLogServer.treeSize if sthOfLogServer is not None else "None"))

        if self.certsAreMissing(logServerEntry, sthOfLogServer): #returns false if sthOfLogServer is None
            requestURL = (logServerEntry.url + "/ct/v1/get-entries?start=" +
                            str(logServerEntry.latest_entry_id + 1) + "&end=" +
                            str(min(logServerEntry.latest_entry_id + 1000, sthOfLogServer.treeSize-1)))
            metadata = {'ct_log_id':logServerEntry.ct_log_id, 'first_entry_id':logServerEntry.latest_entry_id + 1}
            requestedEntries = self.requestEntries(requestURL, metadata)

        return requestedEntries




    def certsAreMissing(self, logServerEntry, sthOfLogServer):
        if sthOfLogServer is None:
            return False

        if (logServerEntry.latest_entry_id == None or
            logServerEntry.latest_entry_id+1 < sthOfLogServer.treeSize):
            return True
        else:
            return False




    def requestSTHOfLogServer(self, logServer):
        try:
            sthRequest = requests.get(logServer.url + "/ct/v1/get-sth")

        except:
            logging.error("Error requesting STH from log server: {}".format(sys.exc_info()[0]))

        else:
            return _SignedTreeHead(sthRequest.json())




    def requestEntries(self, requestURL, metadata):
        try:
            requestedEntries = requests.get(requestURL)

        except:
            logging.error("Error getting Entries")
            exit()

        else:
            processedEntries = []

            requestedEntries = requestedEntries.json()
            
            i = 0
            if not 'entries' in requestedEntries:
                logging.error("'entries' is not a key in requestedEntries")
                print(requestedEntries)
            else:
                for entry in requestedEntries['entries']:
                    entrymetadata = {'ct_log_id':metadata['ct_log_id'], 'entry_id':metadata['first_entry_id']+i}
                    processedEntries.append(_Entry(entry, entrymetadata))
                    i += 1

            return processedEntries





    def populateNewLogEntries(self, newLogEntries):
        for entry in newLogEntries:
                self.populateEntry(entry)
            
        self.connectionToDataBase.commit()


    def populateEntry(self, entry):
        # create CA entries
        ca_certificates = entry.retrieveCaCertificates()
        ca_id = self.populateCaCertificates(ca_certificates)
        # insert certificate
        
        self.populateCertificate(entry, ca_id)


    def populateCertificate(self, entry, ca_id):
        certificate = entry.retrieveCertificate()
        if(ca_id == None): #it's a root certificate
            ca_id = self.populateCaCertificates([certificate])
            
        cert_id = self.insertCertificate(certificate, ca_id)
        
        self.createCtLogEntry(cert_id, entry)
        
        return cert_id
    
    
    def createCtLogEntry(self, cert_id, entry):
        sqlQuery = "INSERT INTO ct_log_entry(CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID, ENTRY_TIMESTAMP) \
            VALUES (%s, %s, %s, %s) \
            ON CONFLICT(CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID) DO NOTHING"
        sqlData = (cert_id, entry.ct_log_id, entry.entry_id, entry.timestamp)
            
        self.cursor.execute(sqlQuery, sqlData)
        
    
    def populateCaCertificates(self, ca_certificates):
        
        if(ca_certificates == None or len(ca_certificates) < 1):
            return None
        
        logging.debug("populating {} CA certificates".format(len(ca_certificates)))
        
        # iterate over ca chain from top to bottom
        last_ca_id = None
        for i in range(len(ca_certificates)-1, -1, -1):
        
            certificate = ca_certificates[i]
            
            subject = certificate.certificate.get_subject()
            commonName = subject.commonName
            
            if commonName == None:
                if subject.organizationName:
                    commonName = "[{}]".format(subject.organizationName)
                else:
                    commonName = "(None)"
            public_key = certificate.certificate.get_pubkey().to_cryptography_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            
            logging.debug("inserting new CA '{}' into CA table".format(commonName))

            sqlQuery = """INSERT INTO ca(COUNTRY_NAME, 
                STATE_OR_PROVINCE_NAME, 
                LOCALITY_NAME, 
                ORGANIZATION_NAME, 
                ORGANIZATIONAL_UNIT_NAME, 
                COMMON_NAME, 
                EMAIL_ADDRESS, 
                PUBLIC_KEY) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) 
            ON CONFLICT(COMMON_NAME,PUBLIC_KEY) DO UPDATE SET COMMON_NAME=ca.COMMON_NAME 
            RETURNING ID"""
            sqlData = (subject.countryName, subject.stateOrProvinceName, 
                       subject.localityName, subject.organizationName, 
                       subject.organizationalUnitName, commonName, 
                       subject.emailAddress, psycopg2.Binary(public_key))
            
            self.cursor.execute(sqlQuery, sqlData)
            new_ca_id = self.cursor.fetchone()[0]
            
            logging.debug("inserted new CA with ID={}".format(new_ca_id))
        
        
            if(last_ca_id == None): # first list entry: be your own root
                last_ca_id = new_ca_id
            
            cert_id = self.insertCertificate(certificate, last_ca_id)
        
            if(cert_id != None):
                sqlQuery = "INSERT INTO ca_certificate (CERTIFICATE_ID, CA_ID) VALUES (%s, %s) ON CONFLICT(CERTIFICATE_ID, CA_ID) DO NOTHING"
                sqlData = (cert_id, new_ca_id)
                self.cursor.execute(sqlQuery, sqlData)
            else:
                logging.error("Could not insert entry into ca_certificate without cert_id")
            
            last_ca_id = new_ca_id
            
        return new_ca_id
        


# don't need that
    #def certificateAlreadyExists(self, certificate):
        ## currently that would be about 33693074 hashes, or 1GB of hash data.
        #hashesOfExistingCertificates = \
            #self.retrieveHashesOfExistingCertificates()

        #if hashesOfExistingCertificates is None:
            #return False

        #for hash in hashesOfExistingCertificates:
            #if certificate.sha256 == hash:
                #return True

        #return False



# don't need that as well
    #def retrieveHashesOfExistingCertificates(self):
        #try:
            #self.cursor.execute("SELECT SHA256 FROM certificate")
            #hashesOfExistingCertificates = self.cursor.fetchall()

        #except:
            #print("Could not retrieve Hashes from DB")

        #else:
            #return hashesOfExistingCertificates




    def insertCertificate(self, certificate, ca_id):
        if(ca_id == None):
            logging.error("Can't insert certificate: No CA given.")
            return None
        logging.debug("Inserting certificate ({})".format(certificate.sha256))
        #try:
        serial = certificate.serial.to_bytes((certificate.serial.bit_length() + 15) // 8, 'big', signed=True) or b'\0'
        sqlQuery = "INSERT INTO certificate (CERTIFICATE, ISSUER_CA_ID, SERIAL, SHA256, NOT_BEFORE, NOT_AFTER, KEY_ALGORITHM, KEY_SIZE, SIGNATURE_ALGORITHM) \
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) \
                        ON CONFLICT (SHA256) DO UPDATE SET SHA256=certificate.SHA256 \
                        RETURNING ID"
        sqlData = (psycopg2.Binary(certificate.certificateBinary), ca_id, serial, certificate.sha256, certificate.notBefore, certificate.notAfter, certificate.keyAlgorithm, certificate.keySize, certificate.signatureAlgorithm)
        self.cursor.execute(sqlQuery, sqlData)
        cert_id = self.cursor.fetchone()[0]
        
        self.insertCertificateIdentity(certificate, cert_id)

        logging.debug("Inserted certificate with ID={}".format(cert_id))
       # except:
        #print("Could not Insert into DB: ", sys.exc_info()[0])

        #else:
        return cert_id
        
        
    def insertCertificateIdentity(self, certificate, cert_id):
        sqlQuery = "INSERT INTO certificate_identity (CERTIFICATE_ID, NAME_TYPE, NAME_VALUE) \
                        VALUES (%s, %s, %s) \
                        ON CONFLICT (CERTIFICATE_ID, lower(NAME_VALUE) text_pattern_ops, NAME_TYPE) DO NOTHING"
        sqlData = []
        
        subject = certificate.certificate.get_subject()

        if(subject.countryName != None):
            sqlData.append((cert_id, 'countryName', subject.countryName))
        if(subject.stateOrProvinceName != None):
            sqlData.append((cert_id, 'stateOrProvinceName', subject.stateOrProvinceName))
        if(subject.localityName != None):
            sqlData.append((cert_id, 'localityName', subject.localityName))
        if(subject.organizationName != None):
            sqlData.append((cert_id, 'organizationName', subject.organizationName))
        if(subject.organizationalUnitName != None):
            sqlData.append((cert_id, 'organizationalUnitName', subject.organizationalUnitName))
        if(subject.commonName != None):
            sqlData.append((cert_id, 'commonName', subject.commonName))
        if(subject.emailAddress != None):
            sqlData.append((cert_id, 'emailAddress', subject.emailAddress))
        for dnsname in certificate.dnsNames:
            sqlData.append((cert_id, 'dNSName', dnsname))

        self.cursor.executemany(sqlQuery, sqlData)
        
        
        
        
        
    def updateCtLogStats(self):
        activeLogServers = self.getActiveLogServers()
        
        for logServer in activeLogServers:
            sqlQuery = "UPDATE ct_log SET LATEST_ENTRY_ID=(SELECT MAX(ENTRY_ID) FROM ct_log_entry WHERE CT_LOG_ID=%s) WHERE ID=%s RETURNING LATEST_ENTRY_ID"
            sqlData = (logServer.ct_log_id, logServer.ct_log_id)
            self.cursor.execute(sqlQuery, sqlData)
            latest_entry_id = self.cursor.fetchone()[0]
            logging.info("LATEST_ENTRY_ID of log {} has been updated to {}".format(logServer.ct_log_id, latest_entry_id))
        self.connectionToDataBase.commit()




class _LogServer:
    def __init__(self, dbEntry):
        self.url = dbEntry[1]
        self.ct_log_id = -1
        self.latest_entry_id = -1
        if dbEntry[0] is not None:
            self.ct_log_id = dbEntry[0]
        if dbEntry[4] is not None:
            self.latest_entry_id = dbEntry[4]





class _SignedTreeHead:
    def __init__(self, sthJSON):
        self.treeSize = sthJSON['tree_size']
        self.timestamp = sthJSON['timestamp']
        self.sha256RootHash = sthJSON['sha256_root_hash']
        self.treeHeadSignature = sthJSON['tree_head_signature']




class _Entry:
    def __init__(self, entryJSON, metadata):
        self.entry_id = metadata['entry_id']
        self.ct_log_id = metadata['ct_log_id']
        self.leafInput = _LeafInput(entryJSON['leaf_input'])
        self.extraData = _ExtraData(entryJSON['extra_data'], self.leafInput.timestampedEntry.entryType)
        self.timestamp = self.leafInput.timestampedEntry.timestamp



    def retrieveCertificate(self):
        if self.leafInput.timestampedEntry.entryType == 0:
            return self.leafInput.timestampedEntry.certificate

        if self.leafInput.timestampedEntry.entryType == 1:
            return self.extraData.certificateChain[0]

        else:
            logging.error("Error retrieving certificate from log entry")
    
    def retrieveCaCertificates(self):
        if self.leafInput.timestampedEntry.entryType == 0:
            return self.extraData.certificateChain

        if self.leafInput.timestampedEntry.entryType == 1:
            if len(self.extraData.certificateChain) > 1:
                return self.extraData.certificateChain[1:]
            else:
                logging.warning("Certificate chain is empty")
                return []

        logging.error("Error retrieving CA certificates from log entry")
        return []





class _LeafInput:
    def __init__(self, leafInput):
        self.leafInput = base64.b64decode(leafInput)
        #self.version = int(self.leafInput[0:1].encode("hex"), 16)
        self.version = int(binascii.hexlify(self.leafInput[0:1]), 16)
        #self.leafType = int(self.leafInput[1:2].encode("hex"), 16)
        self.leafType = int(binascii.hexlify(self.leafInput[1:2]), 16)
        self.timestampedEntry = _TimestampedEntry(self.leafInput)





class _TimestampedEntry():
    def __init__(self, timestampedEntry):
        self.timestampedEntry = timestampedEntry
        #self.timestamp = int(self.timestampedEntry[2:10].encode("hex"), 16)
        self.timestamp = datetime.datetime.fromtimestamp(int(binascii.hexlify(self.timestampedEntry[2:10]), 16) / 1000)
        #self.entryType = int(self.timestampedEntry[10:12].encode("hex"), 16)
        self.entryType = int(binascii.hexlify(self.timestampedEntry[10:12]), 16)
        self.certificate = None
        self.extensions = None

        if self.entryType == 0:
            #certificateSize = int(self.timestampedEntry[12:15].encode("hex"), 16)
            certificateSize = int(binascii.hexlify(self.timestampedEntry[12:15]), 16)
            self.certificate = _Certificate(self.timestampedEntry[15:15 + certificateSize])
        else:
            self.certificate = None





class _Certificate:
    def __init__(self, certificate):
        self.certificateBinary = certificate
        self.certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certificate)
        self.notAfter = parser.parse(self.certificate.get_notAfter())
        self.notBefore = parser.parse(self.certificate.get_notBefore())
        self.serial = self.certificate.get_serial_number()
        self.sha256 = binascii.unhexlify(self.certificate.digest('sha256').replace(b':',b''))
        cryptokey = self.certificate.get_pubkey().to_cryptography_key()
        self.keyAlgorithm = self.getAlgorithmFromKey(cryptokey)
        self.keySize = cryptokey.key_size if hasattr(cryptokey, 'key_size') else None
        try:
            self.signatureAlgorithm = self.certificate.get_signature_algorithm().decode('utf-8')
        except ValueError:
            self.signatureAlgorithm = '__UndefinedSignatureAlgorithm__'
        self.dnsNames = self.extractDnsNames()
        
    def extractDnsNames(self):
        # first we find the subjectAltName extension
        for i in range(self.certificate.get_extension_count()):
            extension = self.certificate.get_extension(i)
            short_name = extension.get_short_name()
            if(short_name == b"subjectAltName"):
                # then we extract the dnsnames from the string representation
                # why? Because it's the easiest way to do it.
                dnsnames = []
                try:
                    for line in str(extension).split(","):
                        m = re.search('DNS:(.+)$',line)
                        if m: 
                            name = m.group(1)
                            dnsnames.append(name)
                    return dnsnames
                except UnicodeDecodeError:
                    return ['__UnicodeDecodeError__']
        return []
    
    def getAlgorithmFromKey(self, key):
        mappings = {'_RSAPublicKey':'RSA','_EllipticCurvePublicKey':'EC','_DSAPublicKey':'DSA'}
        if not key:
            return None
        class_as_string = str(key.__class__.__name__)
        if class_as_string in mappings:
            return mappings[class_as_string]
        else:
            return class_as_string





class _ExtraData:
    def __init__(self, extraData, entryType):
        self.extraData = base64.b64decode(extraData)
        self.entryType = entryType
        self.totalSize = None
        self.certificateChain = []
        self.retrieveCertificates()




    def retrieveCertificates(self):
        if self.entryType == 0:
            self.retrieveX509Certificates()

        if self.entryType == 1:
            self.retrievePreCertificates()




    def retrieveX509Certificates(self):
        #self.totalSize = int(self.extraData[0:3].encode("hex"), 16)
        self.totalSize = int(binascii.hexlify(self.extraData[0:3]), 16)
        combinedCertificateSize = 0
        currentCertificateSize = 0

        while (self.totalSize > combinedCertificateSize):
            #currentCertificateSize = int(
                                         #self.extraData[3 +
                                         #combinedCertificateSize:6 +
                                         #combinedCertificateSize].encode("hex"),16)
            currentCertificateSize = int(
                                         binascii.hexlify(self.extraData[3 +
                                         combinedCertificateSize:6 +
                                         combinedCertificateSize]),16)

            combinedCertificateSize += 3

            currCert = self.extraData[3 + combinedCertificateSize : 3 + combinedCertificateSize + currentCertificateSize]
            currCert = _Certificate(currCert)

            combinedCertificateSize += currentCertificateSize

            self.certificateChain.append(currCert)




    def retrievePreCertificates(self):
        combinedCertificateSize = 0

        #sizeOfFirstCert = int(self.extraData[0:3].encode("hex"), 16)
        sizeOfFirstCert = int(binascii.hexlify(self.extraData[0:3]), 16)
        #sizeOfCertChain = int(self.extraData[3 + sizeOfFirstCert:6 +
                                             #sizeOfFirstCert].encode("hex"),
        sizeOfCertChain = int(binascii.hexlify(self.extraData[3 + sizeOfFirstCert:6 +
                                             sizeOfFirstCert]),
                                                16)
        startOfCertChain = 3 + sizeOfFirstCert


        while (sizeOfCertChain > combinedCertificateSize):
            #currentCertificateSize = int(
                                         #self.extraData[3 +
                                         #startOfCertChain +
                                         #combinedCertificateSize:6 +
                                         #startOfCertChain +
                                         #combinedCertificateSize].
                                            #encode("hex"), 16)
            currentCertificateSize = int(
                                         binascii.hexlify(self.extraData[3 +
                                         startOfCertChain +
                                         combinedCertificateSize:6 +
                                         startOfCertChain +
                                         combinedCertificateSize]), 16)

            combinedCertificateSize += 3

            currCert = self.extraData[3 + startOfCertChain +  combinedCertificateSize:3 +startOfCertChain +combinedCertificateSize + currentCertificateSize]
            currCert = _Certificate(currCert)

            combinedCertificateSize += currentCertificateSize

            self.certificateChain.append(currCert)

class EntryFromLogserverRetrievalThread(threading.Thread):
    def __init__(self, database, logServerEntry, output_queue):
        threading.Thread.__init__(self)
        self.database = database
        self.logServerEntry = logServerEntry
        self.output_queue = output_queue
    
    def getLogServerEntry(self):
        return self.logServerEntry
    
    def run(self):
        entries = database.requestNewEntriesFromServer(self.logServerEntry)
        self.output_queue.put(entries)
                



if __name__ == "__main__":
    argparser = argparse.ArgumentParser(prog='ct-monitor in python')

    argparser.add_argument('-d', help='debug output', action='store_true')
    argparser.add_argument('--dbhost', help='postgres ip or hostname (default localhost)', default='localhost')
    argparser.add_argument('--dbuser', help='postgres user (default postgres)', default='postgres')
    argparser.add_argument('--dbname', help='postgres database name (default certwatch)', default='certwatch')
    argparser.add_argument('--log', help='name of the file the log shall be written to')
    args = argparser.parse_args()
    
    logging_filename = args.log if args.log else None
    logging_level = logging.DEBUG if args.d else logging.INFO
    logging.basicConfig(level=logging_level, filename=logging_filename)
    
    logging.info("Connecting to database (name={name}, user={user}, host={host})".format(name=args.dbname, user=args.dbuser, host=args.dbhost))
    database = connectToDatabase(name=args.dbname, user=args.dbuser, host=args.dbhost)
    
    logging.info("Starting monitor...")
    monitor(database)
    logging.info("Finished monitor.")