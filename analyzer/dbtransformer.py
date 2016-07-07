import psycopg2
import threading

class DBTransformer(threading.Thread):

    def __init__(self, dbname, dbuser, dbhost):
        threading.Thread.__init__(self)
        self.newly_expired_counter = 0
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.db = None
        
    def run():
        self.db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
        self.update_expired_flag()
        self.db.close()

    def update_expired_flag(self):
        cursor = self.db.cursor()
        cursor.execute("UPDATE certificate SET EXPIRED=TRUE WHERE ((x509_notAfter(CERTIFICATE) < NOW() ) AND EXPIRED=FALSE)")
        self.newly_expired_counter += cursor.rowcount
        self.db.commit()

        return self.print_log()

    def print_log(self):
        return "{{'type':'expired','data':{{'new':{} }} }},".format(self.newly_expired_counter)
