import psycopg2

class DBTransformer:

    def __init__(self, db):
        self.newly_expired_counter = 0
        self.db = db

    def update_expired_flag(self):
        cursor = self.db.cursor()
        cursor.execute("UPDATE certificate SET EXPIRED=TRUE WHERE ((x509_notAfter(CERTIFICATE) < NOW() ) AND EXPIRED=FALSE)")
        self.newly_expired_counter += cursor.rowcount
        self.db.commit()

        return self.print_log()

    def print_log(self):
        return "{{'type':'expired','data':{{'new':{} }} }},".format(self.newly_expired_counter)
