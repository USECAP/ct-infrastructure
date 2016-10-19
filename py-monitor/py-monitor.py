import requests
import struct
import base64
import json
import OpenSSL
import psycopg2






class ExtraData(object):
    def __init__(self, b64DecodedExtraData):
        self.extraData = b64DecodedExtraData
        self.totalSize = int(self.extraData[0:3].encode("hex"), 16)





class X509ExtraData(ExtraData):
    def __init__(self, b64DecodedExtraData):
        self.extraData = b64DecodedExtraData
        self.totalSize = int(self.extraData[0:3].encode("hex"), 16)
        self.certificateChain = []


    def retrieveCertificates(self):
        combinedSize = 0
        currentSize = 0

        while (self.totalSize > combinedSize):
            currentSize = int(self.extraData[3 + combinedSize:6 + combinedSize].encode("hex"), 16)

            combinedSize += 3

            currCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, self.extraData[3 + combinedSize:3 + combinedSize + currentSize])
            currCert = Certificate(currCert)

            combinedSize += currentSize

            self.certificateChain.append(currCert)



class PreCertExtraData(ExtraData):
    def __init__(self, b64DecodedExtraData):
        self.extraData = b64DecodedExtraData
        self.totalSize = int(self.extraData[0:3].encode("hex"), 16)
        self.certificate = None
        self.certificateChain = []


    def retrieveCertificates(self):
        i = 0
        combinedSize = 0
        currentSize = 0

        while (self.totalSize > combinedSize):
            currentSize = int(self.extraData[3 + combinedSize:6 + combinedSize].encode("hex"), 16)

            combinedSize += 3

            currCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, self.extraData[3 + combinedSize:3 + combinedSize + currentSize])
            currCert = Certificate(currCert)

            combinedSize += currentSize

            if i == 0:
                self.certificate = currCert
            else:
                self.certificateChain.append(currCert)

            i += 1




class ED(X509ExtraData, PreCertExtraData):
    def __new__(cls, b64DecodedExtraData, logEntryType):
        if logEntryType == 0:
            return X509ExtraData(b64DecodedExtraData)

        if logEntryType == 1:
            return PreCertExtraData(b64DecodedExtraData)





class Certificate:
    def __init__(self, certificate):
        self.certificate = certificate
        self.notAfter = self.certificate.get_notAfter()
        self.notBefore = self.certificate.get_notBefore()
        self.sha256 = self.certificate.digest('sha256'.encode('ascii','ignore'))





class Entry:
    def __init__(self, jsonEntry):
        self.certificate = None
        self.certificateChain = []

        self.entry = jsonEntry
        self.extractLeafData()

        ed = self.entry['extra_data']
        ed = base64.b64decode(ed)
        logEntrType = self.leafInput.logEntryType
        self.extraData = ED(ed, logEntrType)

    def extractLeafData(self):
        leafInput = base64.b64decode(self.entry['leaf_input'])
        self.timestamp = int(leafInput[2:10].encode("hex"), 16)

        entryType = int(leafInput[10:12].encode("hex"), 16)
        if entryType == 0:
            certSize = int(leafInput[12:15].encode("hex"), 16)
            self.certificate = Certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, leafInput[15:15 + certSize]))
        else:
            self.certificate = None


    def extractExtraData(self):
        pass







class SignedTreeHead:
    def __init__(self, sigTH):
        self.version = None
        self.signatureType = None
        self.timestamp = sigTH['timestamp']
        self.treeSize = sigTH['tree_size']
        self.rootHash = sigTH['sha256_root_hash']




dataBase = psycopg2.connect(dbname="certwatch",user="postgres", host="localhost")
cur = dataBase.cursor()

cur.execute("SELECT SHA256 FROM certificate")
bla = cur.fetchall()
print len(bla)



"""
def main():

    rows = cur.fetchall()

    for r in rows:
        sthUrl = r[0] + "/ct/v1/get-sth"

        try:
            sthReq = requests.get(sthUrl)

        except requests.exceptions.RequestException as err:
            print err
            continue

        signedTH = SignedTreeHead(sthReq.json())

        if (r[1]==None or r[1] < signedTH.treeSize):
            entriesUrl = r[0] + "/ct/v1/getentries?start=" + str(r[1]+1) +"&end=" + str(r[1]+1001)
            entriesReq = requests.get(entriesUrl)

            for entry in entriesReq:
                e = Entry(entry.json())
"""
                #cur.execute("""SELECT ID FROM certificate WHERE e.""")
"""











main()

"""