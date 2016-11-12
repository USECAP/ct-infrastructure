import psycopg2
import logging
import threading

import smtplib
from email.mime.text import MIMEText

URL = "https://www.ct-observatory.org"
FROM_ADDRESS = 'noreply@ct-observatory.org'
SMTP_HOST = 'localhost'
SMTP_PORT = 587
SMTP_USER = 'smtpuser'
SMTP_PASS = 'smtppass'

class Notifier(threading.Thread):
    def __init__(self, dbname, dbuser, dbhost):
        threading.Thread.__init__(self)
        self.dbname = dbname
        self.dbuser = dbuser
        self.dbhost = dbhost
        self.db = None
        self.notified = 0
        self.logger = logging.getLogger(__name__)

    def run(self):
        self.db = psycopg2.connect(dbname=self.dbname, user=self.dbuser, host=self.dbhost)
        self.notify()
        self.db.close()
        
    def initialize(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT value from certificate_analysis where type='notifier_last_cert_id'")
        if len(cursor.fetchall()) == 0:
            cursor.execute("INSERT INTO certificate_analysis (type,value) VALUES ('notifier_last_cert_id',(SELECT max(id) from certificate))")

    def notify(self):
        cursor = self.db.cursor()
        
        self.logger.debug("Initializing database")
        self.initialize()

        #cursor.execute("select CASE when ne.notify_for=0 or (ne.notify_for=1 and ci.name_type='dNSName') or (ne.notify_for=2 and ci.name_type='commonName') then true else false end as notify,  ne.email, ndn.name, ci.name_type, ca.name, x509_notBefore(c.certificate)  from notification_email ne inner join notification_dns_names ndn on ne.notification_dns_names_id = ndn.id inner join certificate_identity ci on ndn.name=ci.name_value and (ci.name_type='commonName' or ci.name_type='dNSName') inner join certificate c on ci.certificate_id = c.id inner join ca on ci.issuer_ca_id = ca.id WHERE ne.validated AND ne.active AND c.id > (SELECT value from certificate_analysis where type='notifier_last_cert_id'); ")
        
        cursor.execute("SELECT value FROM certificate_analysis WHERE type='notifier_last_cert_id'")
        retval = cursor.fetchone()
        min_id = retval[0]
        cursor.execute("SELECT max(id) FROM certificate")
        retval = cursor.fetchone()
        max_id = retval[0]
        self.logger.debug("Examining certificates with {0} < id <= {1}".format(min_id, max_id))
        
        notifications = {}
        cursor.execute("SELECT e.email, e.notify_for, n.name FROM notification_email e JOIN notification_dns_names n ON e.notification_dns_names_id = n.id WHERE e.active ORDER BY e.email ASC")
        
        for record in cursor:
            email = record[0]
            notify_for = record[1]
            name = record[2]
            
            if(email not in notifications):
                notifications[email] = []
            notifications[email].append((name, notify_for))
        self.logger.debug("Found {0} email addresses for notification".format(len(notifications)))
        
        
        for email in notifications:
            new_certificates = {}
            count = 0
            for name, notify_for in notifications[email]:
                if name not in new_certificates:
                    new_certificates[name] = []
                if(notify_for in (0,2)): #CN
                    self.logger.debug("Searching for CN={0}".format(name))
                    cursor.execute("SELECT c.id, c.certificate FROM certificate c JOIN certificate_identity ci ON c.ID = ci.CERTIFICATE_ID WHERE c.ID >  %(min_id)s AND c.ID <= %(max_id)s AND ci.NAME_TYPE = 'commonName' AND reverse(lower(ci.NAME_VALUE)) = reverse(lower(%(cn)s))", {'cn':name, 'min_id':min_id, 'max_id':max_id})
                    
                    for cert_id, certificate in cursor:
                        new_certificates[name].append((cert_id, certificate))
                        count += 1
                        
                if(notify_for in (0,1)): #dNSName
                    self.logger.debug("Searching for DNSNAME={0}".format(name))
                    cursor.execute("SELECT c.id, c.certificate FROM certificate c JOIN certificate_identity ci ON c.id = ci.certificate_id WHERE c.id >  %(min_id)s AND c.id <= %(max_id)s AND ci.name_type = 'dNSName' AND reverse(lower(ci.name_value))=reverse(lower(%(dnsname)s))", {'dnsname':name, 'min_id':min_id, 'max_id':max_id})
                    
                    for cert_id, certificate in cursor:
                        new_certificates[name].append((cert_id, certificate))
                        count += 1
            if(count > 0):
                email_subject = "[ct-observatory] Found {0} new certificates".format(count)
                email_text = "The CT observatory found new certificates for the CN / DNSNames you subscribed to:\n\n"
            
                for name in new_certificates:
                    email_text += name
                    email_text += "\n"
                    email_text += (len(name) * "=")
                    email_text += "\n\n"
                
                    if(len(new_certificates[name]) == 0):
                        email_text += "No new certificates found.\n"
                
                    for cert_id, certificate in new_certificates[name]:
                        email_text += "{url}/cert/{cert_id}/\n".format(url=URL, cert_id=cert_id)
                    email_text += "\n"
                
                msg = MIMEText(email_text)
                msg['Subject'] = email_subject
                msg['From'] = FROM_ADDRESS
                msg['To'] = email
                
                self.logger.debug("Sending E-Mail to {0}".format(email))
                print(msg)
                
                #try:
                    #s = smtplib.SMTP(SMTP_HOST,SMTP_PORT)
                    #s.ehlo()
                    #s.starttls()
                    #s.login(SMTP_USER, SMTP_PASS)
                    #s.sendmail(FROM_ADDRESS, [email], msg.as_string())
                    #s.quit()
                #except:
                    # self.logger.error('failed to send email to {0}'.format(email))
        

        #for notify in cursor.fetchall():
            #self.logger.debug((notify,"JAAA"))
        
        self.logger.debug("Setting notifier_last_cert_id={0}".format(max_id))
        #cursor.execute("UPDATE certificate_analysis SET value=%(max_id)s where type='notifier_last_cert_id'", {'max_id':max_id})
        #TODO

        self.db.commit()

        self.logger.info( self.print_log() )

    def print_log(self):
        return "{{'type':'notifier', 'data':{{ }},".format()

# get min cert id

# for email in notify:
# SELECT e.email, e.notify_for, n.name FROM notification_email e JOIN notification_dns_names n ON e.notification_dns_names_id = n.id WHERE e.active ORDER BY e.email ASC

	# for X = cn/dnsname in notify[email]:

	#	select certificates with id > min cert id and cn/dnsname == X
	#	SELECT id, certificate FROM certificate WHERE id > (SELECT value FROM certificate_analysis WHERE type='notifier_last_cert_id') AND x509_commonName(certificate) = <CN>;
	#	SELECT c.id, c.certificate FROM certificate c JOIN certificate_identity ci ON c.id = ci.certificate_id WHERE c.id > (SELECT value FROM certificate_analysis WHERE type='notifier_last_cert_id') AND ci.name_type = 'dNSName' AND ci.name_value = <DNSNAME>;

# update min cert id