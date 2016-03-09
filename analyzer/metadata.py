import psycopg2


class Metadata:
    def __init__(self, db):
        self.db = db

    def update_metadata(self):
        cursor = self.db.cursor()

        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM certificate) WHERE NAME_TYPE='number_of_certs'")  # All Certs
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM ca) WHERE NAME_TYPE='number_of_cas'")  # All CA
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM certificate where not expired) WHERE NAME_TYPE='number_of_active_certs'")  # ACTIVE
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM certificate where expired) WHERE NAME_TYPE='number_of_expired_certs'")  # EXPIRED
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(SELECT COUNT(*) FROM revoked_certificate) WHERE NAME_TYPE='number_of_revoked_certs'")  # REVOKED
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_misissued_certs'")  # Misissued
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_correctly_behaving_cas'")  # Correct CA
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=0 WHERE NAME_TYPE='number_of_interesting_cas'")  # Suspicious CA
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(select max(latest_entry_id) from ct_log) WHERE NAME_TYPE='number_of_certs_in_biggest_log'")  # Max log
        cursor.execute(
            "UPDATE metadata SET NAME_VALUE=(select min(latest_entry_id) from ct_log) WHERE NAME_TYPE='number_of_certs_in_smallest_log'")  # Min log

        self.db.commit()

        return self.print_log()

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
