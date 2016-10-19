import psycopg2
import requests
import base64
import OpenSSL
import sys





def connectToDatabase(name="certwatch", user="postgres", host="localhost"):
    database = _LocalDatabase(name, user, host)
    return database




def monitor(database):
    newLogEntries = database.retrieveNewLogEntries()
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
            print "Error connecting to local database"
            exit()




    def retrieveNewLogEntries(self):
        newLogEntries = []
        activeLogServers = self.getActiveLogServers()

        for activeLogServer in activeLogServers:
            newLogEntries += self.requestNewEntriesFromServer(activeLogServer)

        return newLogEntries




    def getActiveLogServers(self):
        try:
            self.cursor.execute("""SELECT * FROM ct_log as ctl WHERE ctl.IS_ACTIVE = TRUE""")
            activeLogServerEntries = self.cursor.fetchall()

        except:
            print "Could not execute Active Log Server Entries Query. ", sys.exc_info()[0]
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
            print "Error requesting STH from log server: ", sys.exc_info()[0]

        else:
            return _SignedTreeHead(sthRequest.json())




    def requestEntries(self, requestURL):
        try:
            requestedEntries = requests.get(requestURL)

        except:
            print "Error getting Entries"
            exit()

        else:
            processedEntries = []

            requestedEntries = requestedEntries.json()

            for entry in requestedEntries['entries']:
                processedEntries.append(_Entry(entry))

            return processedEntries





    def populateNewLogEntries(self, newLogEntries):
        for entry in newLogEntries:
            certificate = entry.retrieveCertificate()
            self.populateCertificate(certificate)



    def populateCertificate(self, certificate):
        if not self.certificateAlreadyExists(certificate):
            self.insertCertificate(certificate)




    def certificateAlreadyExists(self, certificate):
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
            print "Could not retrieve Hashes from DB"

        else:
            return hashesOfExistingCertificates




    def insertCertificate(self, certificate):
        #try:
        sqlQuery = "INSERT INTO certificate (CERTIFICATE, ISSUER_CA_ID, SHA256) \
                        VALUES (%s, %s, %s)"
        sqlData = (psycopg2.Binary(certificate.certificateBinary), "1", certificate.sha256, )
        self.cursor.execute(sqlQuery, sqlData)
        hashesOfExistingCertificates = self.cursor.fetchall()

       # except:
        print "Could not Insert into DB: ", sys.exc_info()[0]

        #else:
        return hashesOfExistingCertificates






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
            print "Error retrieving certificate from log entry"





class _LeafInput:
    def __init__(self, leafInput):
        self.leafInput = base64.b64decode(leafInput)
        self.version = int(self.leafInput[0:1].encode("hex"), 16)
        self.leafType = int(self.leafInput[1:2].encode("hex"), 16)
        self.timestampedEntry = _TimestampedEntry(self.leafInput)





class _TimestampedEntry():
    def __init__(self, timestampedEntry):
        self.timestampedEntry = timestampedEntry
        self.timestamp = int(self.timestampedEntry[2:10].encode("hex"), 16)
        self.entryType = int(self.timestampedEntry[10:12].encode("hex"), 16)
        self.certificate = None
        self.extensions = None

        if self.entryType == 0:
            certificateSize = int(self.timestampedEntry[12:15].encode("hex"),
                                    16)
            self.certificate = _Certificate(self.timestampedEntry[15:15 + certificateSize])
        else:
            self.certificate = None





class _Certificate:
    def __init__(self, certificate):
        self.certificateBinary = certificate
        self.certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certificate)
        self.notAfter = self.certificate.get_notAfter()
        self.notBefore = self.certificate.get_notBefore()
        self.sha256 = self.certificate.digest('sha256'.encode('ascii',
                                                              'ignore'))





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
        self.totalSize = int(self.extraData[0:3].encode("hex"), 16)
        combinedCertificateSize = 0
        currentCertificateSize = 0

        while (self.totalSize > combinedCertificateSize):
            currentCertificateSize = int(
                                         self.extraData[3 +
                                         combinedCertificateSize:6 +
                                         combinedCertificateSize].
                                            encode("hex"),16)

            combinedCertificateSize += 3

            currCert = self.extraData[3 + combinedCertificateSize : 3 + combinedCertificateSize + currentCertificateSize]
            currCert = _Certificate(currCert)

            combinedCertificateSize += currentCertificateSize

            self.certificateChain.append(currCert)




    def retrievePreCertificates(self):
        combinedCertificateSize = 0

        sizeOfFirstCert = int(self.extraData[0:3].encode("hex"), 16)
        sizeOfCertChain = int(self.extraData[3 + sizeOfFirstCert:6 +
                                             sizeOfFirstCert].encode("hex"),
                                                16)
        startOfCertChain = 3 + sizeOfFirstCert


        while (sizeOfCertChain > combinedCertificateSize):
            currentCertificateSize = int(
                                         self.extraData[3 +
                                         startOfCertChain +
                                         combinedCertificateSize:6 +
                                         startOfCertChain +
                                         combinedCertificateSize].
                                            encode("hex"), 16)

            combinedCertificateSize += 3

            currCert = self.extraData[3 + startOfCertChain +  combinedCertificateSize:3 +startOfCertChain +combinedCertificateSize + currentCertificateSize]
            currCert = _Certificate(currCert)

            combinedCertificateSize += currentCertificateSize

            self.certificateChain.append(currCert)




if __name__ == "__main__":
    database = connectToDatabase()
    monitor(database)