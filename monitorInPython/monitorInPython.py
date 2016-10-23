import psycopg2
import requests
import base64
import OpenSSL
import sys
import logging
import argparse
import re
import cryptography
import binascii
from dateutil import parser




def connectToDatabase(name="certwatch", user="postgres", host="localhost"):
    database = _LocalDatabase(name, user, host)
    return database




def monitor(database):
    logging.debug("Retrieving new log entries")
    newLogEntries = database.retrieveNewLogEntries()
    logging.debug("Populating new log entries")
    database.populateNewLogEntries(newLogEntries)





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
            print("Error connecting to local database")
            exit()




    def retrieveNewLogEntries(self):
        newLogEntries = []
        activeLogServers = self.getActiveLogServers()

        for activeLogServer in activeLogServers:
            logging.debug("Querying {}...".format(activeLogServer.url))
            newLogEntries += self.requestNewEntriesFromServer(activeLogServer)

        return newLogEntries




    def getActiveLogServers(self):
        try:
            self.cursor.execute("""SELECT * FROM ct_log as ctl WHERE ctl.IS_ACTIVE = TRUE""")
            activeLogServerEntries = self.cursor.fetchall()

        except:
            print("Could not execute Active Log Server Entries Query. ", sys.exc_info()[0])
            exit()

        else:
            activeLogServers = []
            for activeLogServerEntry in activeLogServerEntries:
                activeLogServers.append(_LogServer(activeLogServerEntry))

            return activeLogServers





    def requestNewEntriesFromServer(self, logServerEntry):
        requestedEntries = []

        if self.certsAreMissing(logServerEntry):
            requestURL = (logServerEntry.url + "/ct/v1/get-entries?start=" +
                            str(logServerEntry.size + 1) + "&end=" +
                            str(logServerEntry.size + 1001))
            requestedEntries = self.requestEntries(requestURL)

        return requestedEntries




    def certsAreMissing(self, logServerEntry):
        sthOfLogServer = self.requestSTHOfLogServer(logServerEntry)

        if sthOfLogServer is None:
            return False

        if (logServerEntry.size == None or
            logServerEntry.size < sthOfLogServer.treeSize):
            return True
        else:
            return False




    def requestSTHOfLogServer(self, logServer):
        try:
            sthRequest = requests.get(logServer.url + "/ct/v1/get-sth")

        except:
            print("Error requesting STH from log server: ", sys.exc_info()[0])

        else:
            return _SignedTreeHead(sthRequest.json())




    def requestEntries(self, requestURL):
        try:
            requestedEntries = requests.get(requestURL)

        except:
            print("Error getting Entries")
            exit()

        else:
            processedEntries = []

            requestedEntries = requestedEntries.json()

            for entry in requestedEntries['entries']:
                processedEntries.append(_Entry(entry))

            return processedEntries





    def populateNewLogEntries(self, newLogEntries):
        for entry in newLogEntries:
            # create CA entries
            ca_certificates = entry.retrieveCaCertificates()
            ca_id = self.populateCaCertificates(ca_certificates)
            # insert certificate
            certificate = entry.retrieveCertificate()
            self.populateCertificate(certificate, ca_id)
        self.connectionToDataBase.commit()



    def populateCertificate(self, certificate, ca_id):
        if not self.certificateAlreadyExists(certificate):
            return self.insertCertificate(certificate, ca_id)
        
        return None
    
    
    def populateCaCertificates(self, ca_certificates):
        
        if(ca_certificates == None or len(ca_certificates) < 1):
            return None
        
        logging.debug("populating {} CA certificates".format(len(ca_certificates)))
        
        certificate = ca_certificates[0]
        
        name = certificate.certificate.get_subject().commonName
        if name == None:
            name = "None"
        public_key = certificate.certificate.get_pubkey().to_cryptography_key().public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER, cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)
        
        
        logging.debug("inserting new CA '{}' into CA table".format(name))
        
        sqlQuery = "INSERT INTO ca(NAME, PUBLIC_KEY) VALUES (%s, %s) \
                    ON CONFLICT(NAME,PUBLIC_KEY) DO UPDATE SET NAME=ca.NAME RETURNING ID"
        sqlData = (name, psycopg2.Binary(public_key))
        self.cursor.execute(sqlQuery, sqlData)
        new_ca_id = self.cursor.fetchone()[0]
        
        logging.debug("inserted new CA with ID={}".format(new_ca_id))
        
        
        ca_id = -1
        if(len(ca_certificates) > 1): 
            ca_id = self.populateCaCertificates(ca_certificates[1:])
        else: # be your own root
            ca_id = new_ca_id
            
        cert_id = self.populateCertificate(certificate, ca_id)
        
        if(cert_id != None):
            sqlQuery = "INSERT INTO ca_certificate (CERTIFICATE_ID, CA_ID) VALUES (%s, %s)"
            sqlData = (cert_id, ca_id)
            self.cursor.execute(sqlQuery, sqlData)
            
        return new_ca_id
        



    def certificateAlreadyExists(self, certificate):
        # currently that would be about 33693074 hashes, or 1GB of hash data.
        hashesOfExistingCertificates = \
            self.retrieveHashesOfExistingCertificates()

        if hashesOfExistingCertificates is None:
            return False

        for hash in hashesOfExistingCertificates:
            if certificate.sha256 == hash:
                return True

        return False




    def retrieveHashesOfExistingCertificates(self):
        try:
            self.cursor.execute("SELECT SHA256 FROM certificate")
            hashesOfExistingCertificates = self.cursor.fetchall()

        except:
            print("Could not retrieve Hashes from DB")

        else:
            return hashesOfExistingCertificates




    def insertCertificate(self, certificate, ca_id):
        if(ca_id == None):
            logging.error("Can't insert certificate: No CA given.")
            return None
        logging.debug("Inserting certificate ({})".format(certificate.sha256))
        #try:
        sqlQuery = "INSERT INTO certificate (CERTIFICATE, ISSUER_CA_ID, SHA256, NOT_BEFORE, NOT_AFTER) \
                        VALUES (%s, %s, %s, %s, %s) \
                        ON CONFLICT (SHA256) DO UPDATE SET SHA256=certificate.SHA256 \
                        RETURNING ID"
        sqlData = (psycopg2.Binary(certificate.certificateBinary), ca_id, certificate.sha256, certificate.notBefore, certificate.notAfter)
        self.cursor.execute(sqlQuery, sqlData)
        cert_id = self.cursor.fetchone()[0]

        logging.debug("Inserted certificate with ID={}".format(cert_id))
       # except:
        #print("Could not Insert into DB: ", sys.exc_info()[0])

        #else:
        return cert_id




class _LogServer:
    def __init__(self, dbEntry):
        self.url = dbEntry[1]
        self.size = 0
        if dbEntry[4] is not None:
            self.size = dbEntry[4]





class _SignedTreeHead:
    def __init__(self, sthJSON):
        self.treeSize = sthJSON['tree_size']
        self.timestamp = sthJSON['timestamp']
        self.sha256RootHash = sthJSON['sha256_root_hash']
        self.treeHeadSignature = sthJSON['tree_head_signature']




class _Entry:
    def __init__(self, entryJSON):
        self.leafInput = _LeafInput(entryJSON['leaf_input'])
        self.extraData = _ExtraData(entryJSON['extra_data'], self.leafInput.timestampedEntry.entryType)



    def retrieveCertificate(self):
        if self.leafInput.timestampedEntry.entryType == 0:
            return self.leafInput.timestampedEntry.certificate

        if self.leafInput.timestampedEntry.entryType == 1:
            return self.extraData.certificateChain[0]

        else:
            print("Error retrieving certificate from log entry")
    
    def retrieveCaCertificates(self):
        if(len(self.extraData.certificateChain) == 1):
            self.extraData.certificateChain[0]
        else:
            return self.extraData.certificateChain[1:]





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
        self.timestamp = int(binascii.hexlify(self.timestampedEntry[2:10]), 16)
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
        self.sha256 = self.certificate.digest('sha256')
        self.dnsNames = self.extractDnsNames()
        
    def extractDnsNames(self):
        # first we find the subjectAltName extension
        for i in range(self.certificate.get_extension_count()):
            extension = self.certificate.get_extension(i)
            short_name = extension.get_short_name()
            if(short_name == "subjectAltName"):
                # then we extract the dnsnames from the string representation
                # why? Because it's the easiest way to do it.
                dnsnames = []
                for line in str(extension).split(","):
                    m = re.search('DNS:(.+)$',line)
                    if m: 
                        name = m.group(1)
                        dnsnames.append(name)
                return dnsnames





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