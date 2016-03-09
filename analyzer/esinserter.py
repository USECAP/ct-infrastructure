import psycopg2
from elasticsearch import Elasticsearch

class ESInserter:

    def __init__(self, db, host_es):
        self.new_inserted = 0
        self.db = db
        self.host_es = host_es

    def update_database(self):
        es = Elasticsearch(self.host_es)
        es.indices.create(index='ct', ignore=400)

        cursor = self.db.cursor()
        cursor.execute("select max(id) from certificate;")
        maxId = cursor.fetchall()[0][0]
        cursor.execute("select value from certificate_analysis where type='es_last_cert_id';")
        last_id = cursor.fetchall()[0][0]
        while last_id < maxId :
            cursor.execute("SELECT id, x509_commonName(certificate) as cn, x509_keyAlgorithm(certificate) as algo, x509_keySize(certificate) as size, x509_notAfter(certificate) as notafter, x509_notBefore(certificate) as notbefore, x509_issuerName(certificate) as issuer, count(*) as dnsnames from (SELECT id, certificate, x509_altNames(certificate) from certificate where not x509_canIssueCerts(certificate) and id > (SELECT value from certificate_analysis where type='es_last_cert_id')) as foo group by id, certificate order by id LIMIT 10000;")
            for row in cursor.fetchall():
                es.create(id=row[0],index='ct', ignore=409,doc_type='certificate',body={'cn':row[1],'algo':row[2],'size':row[3],'notafter':row[4],'notbefore':row[5], 'issuer':row[6],'dnsnames':int(row[7])})
                last_id=row[0]
            print(last_id)
            self.new_inserted += cursor.rowcount
            cursor.execute("UPDATE certificate_analysis SET value={} WHERE type='es_last_cert_id'".format(last_id))
            self.db.commit()

        return self.print_log()

    def print_log(self):
        return "{{'type':'es','data':{{'new':{} }} }},".format(self.new_inserted)
