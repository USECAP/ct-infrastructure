import psycopg2
import logging
import threading


class Metadata(threading.Thread):
    def __init__(self, dbname, dbuser, dbhost):
        threading.Thread.__init__(self)
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.db = None
        self.logger = logging.getLogger(__name__)
        
    def run(self):
        self.db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
        self.update_metadata()
        self.db.close()

    def update_metadata(self):
        cursor = self.db.cursor()

        self.logger.debug("counting all certificates")
        cursor.execute(
            #"UPDATE metadata SET NAME_VALUE=(SELECT reltuples FROM pg_class WHERE relname = 'certificate') WHERE NAME_TYPE='number_of_certs'")  # All Certs
            "UPDATE metadata SET NAME_VALUE=(SELECT count(*) FROM certificate) WHERE NAME_TYPE='number_of_certs'")  # All Certs
	
	self.logger.debug("counting all CAs")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM ca) WHERE NAME_TYPE='number_of_cas'")  # All CA
	
	self.logger.debug("counting expired certificates")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM certificate where expired) WHERE NAME_TYPE='number_of_expired_certs'")  # EXPIRED
	
	self.logger.debug("counting revoked certificates")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM revoked_certificate) WHERE NAME_TYPE='number_of_revoked_certs'")  # REVOKED
	
	self.logger.debug("counting active certificates")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=((SELECT NAME_VALUE FROM metadata WHERE NAME_TYPE='number_of_certs') - (SELECT NAME_VALUE FROM metadata WHERE NAME_TYPE='number_of_expired_certs') - (SELECT COUNT(*) FROM revoked_certificate rc JOIN certificate c ON rc.certificate_id = c.id WHERE NOT c.expired )) WHERE NAME_TYPE='number_of_active_certs'")  # ACTIVE
	
	self.logger.debug("'counting' misissued certificates")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_misissued_certs'")  # Misissued
	
	self.logger.debug("'counting' correctly behaving CAs")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_correctly_behaving_cas'")  # Correct CA
	
	self.logger.debug("'counting' number of interesting CAs")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_interesting_cas'")  # Suspicious CA
	
	self.logger.debug("determining number_of_certs_in_biggest_log")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(select max(latest_entry_id) from ct_log) WHERE NAME_TYPE='number_of_certs_in_biggest_log'")  # Max log
	
	self.logger.debug("determining number_of_certs_in_smallest_log")
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(select min(latest_entry_id) from ct_log) WHERE NAME_TYPE='number_of_certs_in_smallest_log'")  # Min log

        self.db.commit()

        self.logger.info(self.print_log())

    def print_log(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT NAME_TYPE, NAME_VALUE from metadata")
        values = {}
        for key,val in cursor.fetchall():
            values[key] = val
        return "{{'type':'meta', 'data':{{'cert':{{'all':{},'active':{},'expired':{},'revoked':{},'misissued':{} }},'ca':{{'all':{},'ok':{},'interesting':{}}},'log':{{'biggest':{},'smallest':{} }} }},".format(
                values['number_of_certs'],values['number_of_active_certs'],values['number_of_expired_certs'],values['number_of_revoked_certs'],values['number_of_misissued_certs'],
                values['number_of_cas'],values['number_of_correctly_behaving_cas'],values['number_of_interesting_cas'],
                values['number_of_certs_in_biggest_log'],values['number_of_certs_in_smallest_log'])
