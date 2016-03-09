Python-script that searches for all listed CRL-Filed notated in all certs of CT-Monitor database and tries to insert an entry into revoked_certificate-table if it finds any new revoked certificates.

Usage:
python analyzer.py [HOSTNAME/IP OF DATABASE (defaults to localhost)]
