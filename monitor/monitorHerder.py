#! /usr/bin/env python3

import threading
import subprocess
import sys
import signal
import argparse
import logging
import psycopg2

stopevent = threading.Event()

def signal_handler(signal, frame):
	print('You pressed Ctrl+C!')
	global stopevent
	stopevent.set()

def getActiveLogServers(database):
	try:
		cursor = database.cursor()
		cursor.execute("""SELECT ID
			FROM ct_log 
			WHERE IS_ACTIVE""")
		
		activeLogServerEntries = cursor.fetchall()

	except:
		logging.error("Could not execute Active Log Server Entries Query. {}".format(sys.exc_info()[0]))
		sys.exit()

	else:
		activeLogServers = []
		for log_id in activeLogServerEntries:
			activeLogServers.append(log_id[0])

		return activeLogServers




class MonitorRepeatThread(threading.Thread):
	
	def __init__(self, log_id, event, dbname=None, dbuser=None,dbhost=None, debug=None, warnings=None):
		threading.Thread.__init__(self)
		self.log_id = log_id
		self.dbhost = dbhost
		self.dbuser = dbuser
		self.dbname = dbname
		self.debug = debug
		self.warnings = warnings
		self.stop = event
	
	def run(self):
		arguments = ["python3", "monitorInPython.py", "--log={}".format(self.log_id)]
		
		if self.dbhost:
			arguments.append("--dbhost={}".format(self.dbhost))
		if self.dbuser:
			arguments.append("--dbuser={}".format(self.dbuser))
		if self.dbname:
			arguments.append("--dbname={}".format(self.dbname))
		if self.debug:
			arguments.append("-d")
		if self.warnings:
			arguments.append("-w")
		
		while not self.stop.is_set():
			subprocess.call(arguments)


if __name__ == "__main__":
	argparser = argparse.ArgumentParser(prog='ct-monitor herder in python')

	argparser.add_argument('-d', help='debug output', action='store_true')
	argparser.add_argument('-w', help='log only warnings and above', action='store_true')
	argparser.add_argument('--dbhost', help='postgres ip or hostname (default localhost)', default='localhost')
	argparser.add_argument('--dbuser', help='postgres user (default postgres)', default='postgres')
	argparser.add_argument('--dbname', help='postgres database name (default certwatch)', default='certwatch')
	args = argparser.parse_args()
	
	logging_level = logging.DEBUG if args.d else logging.INFO
	logging_level = logging.WARNING if args.w else logging_level
	logging.basicConfig(level=logging_level)
	
	logging.info("Querying all active logs")
	
	logging.info("Connecting to database (name={name}, user={user}, host={host})".format(name=args.dbname, user=args.dbuser, host=args.dbhost))
	
	database = psycopg2.connect(dbname=args.dbname, user=args.dbuser, host=args.dbhost)
	
	activeLogServers = getActiveLogServers(database)
	
	
	for log_id in activeLogServers:
		logging.info("Starting monitor thread for id {}...".format(log_id))
		thread = MonitorRepeatThread(log_id, stopevent, args.dbname, args.dbuser, args.dbhost, args.d, args.w)
		thread.start()
		
	logging.info("All threads started.")
	
	signal.signal(signal.SIGINT, signal_handler)

