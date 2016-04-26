import psycopg2
from elasticsearch import Elasticsearch

class ESInserter:

    def __init__(self, db, host_es):
        self.insert_successful = 0
        self.insert_failed = 0
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
        print('max_id',maxId, ' lastid: ',last_id)

        while last_id < maxId :
            cursor.execute("SELECT id, x509_commonName(certificate) AS cn, x509_keyAlgorithm(certificate) AS algo, x509_keySize(certificate) AS size, x509_notAfter(certificate) AS notafter, x509_notBefore(certificate) AS notbefore, x509_issuerName(certificate) AS issuer, count(*) AS dnsnames FROM (SELECT id, certificate, x509_altNames(certificate) FROM certificate WHERE id IN (SELECT id FROM certificate WHERE NOT x509_canIssueCerts(certificate) AND id > (SELECT value FROM certificate_analysis  WHERE type='es_last_cert_id') ORDER BY id ASC LIMIT 1000)) AS foo GROUP BY id, certificate ORDER BY id ASC;")
            certs_to_update = cursor.fetchall()

            if not certs_to_update:
                break

            print("fetched: ",len(certs_to_update))

            for row in certs_to_update:
                res = es.create(id=row[0],index='ct', ignore=409,doc_type='certificate',body={'cn':row[1],'algo':row[2],'size':row[3],'notafter':row[4],'notbefore':row[5], 'issuer':row[6],'dnsnames':int(row[7])})
                last_id=row[0]
                if res['created']:
                    self.insert_successful += 1
                else:
                    self.insert_failed += 1

            print(last_id)
            cursor.execute("UPDATE certificate_analysis SET value={} WHERE type='es_last_cert_id'".format(last_id))
            self.db.commit()

        return self.print_log()

    def print_log(self):
        return "{{'type':'es','data':{{'total':{}, 'success':{}, 'failed':{} }} }},".format(self.insert_successful+self.insert_failed, self.insert_successful, self.insert_failed)
