import socket
from struct import *
import sys
import threading
import pcapy
import config
import client
import utils

def startClient():
	# check if you can connect?
	# start the recieving thread
	listenThread = threading.Thread(target=recvThread)
	listenThread.daemon = True
	listenThread.start()

	# wait for commands
	while(client.running):
		comm = getCommand()
		if comm != "":
			sendCommand(utils.encryptData(comm))
		else:
			client.running = False

	listenThread.stop()

def sendCommand(command):
	# send your command, make sure you set the password in the ip id field (ipHeader[3])
	print "sendCommand"

def recvThread():
	# wait for the knock code
	# once you get the knock code, send something back, then begin listening for stuff
	# for now, just print data
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	cap.setfilter(config.protocol)

	while(client.running):
		(header, packet) = cap.next()
		if authenticated():
			packetHandler(packet)
		else

def packetHandler(packet):
	print packet

def getCommand():
	try: 
		comm = raw_input()
	except KeyboardInterrupt:
		return ""
	return comm
