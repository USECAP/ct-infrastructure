import psycopg2

class DBTransformer:

    def __init__(self, db, log=True):
        self.newly_expired_counter = 0
        self.log = log
        self.db = db

    def update_expired_flag(self):
        cursor = self.db.cursor()
        cursor.execute("UPDATE certificate SET EXPIRED=TRUE WHERE ((x509_notAfter(CERTIFICATE) < NOW() ) AND EXPIRED=FALSE)")
        self.newly_expired_counter += cursor.rowcount
        self.db.commit()

        if self.log:
            self.print_log()

    def print_log(self):
        print "{{'type':'expired','data':{{'new':{} }} }},".format(self.newly_expired_counter)
