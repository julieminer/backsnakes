"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    utils.py
--
--  PROGRAM:        utils
--
--  FUNCTIONS:      covertPacket(address, protocol, char, pswd)
--					finPacket(address, protocol, pswd)
--					stripPacket(packet, proto)
--					checkType(packet)
--					encrypt(phrase)
--					encryptData(data)
--					decryptData(data)
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			Several various functions that need to be used in multiple modules.
--  
---------------------------------------------------------------------------------------*/
"""

from struct import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import config

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   covertPacket(address, protocol, char, pswd)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	covertPacket(address, protocol, char, pswd)
--						address - the destination IP address
--						protocol - the protocol to use 
--						char - the character to embed in the packet
--						pswd - the password, used for authentication
--
--  RETURNS:  	packet - the covert packet, with data embedded in it
--
--  NOTES:  	builds a covert packet to send to address, using protocol, char, and pswd
--  
------------------------------------------------------------------------------*/
"""	
def covertPacket(address, protocol, char, pswd):
	packet = IP(dst=address, id=pswd)
	if protocol == 'tcp':
		proto = TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=ord(char))
	elif protocol == 'udp':
		proto = UDP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), chksum=ord(char))
	elif protocol == 'icmp':
		proto = ICMP(chksum=ord(char))
	packet = packet/proto
	return packet

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   finPacket(address, protocol, pswd)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	finPacket(address, protocol, pswd)
--						address - the destination IP address
--						protocol - the protocol to use 
--						pswd - the password, used for authentication
--
--  RETURNS:  	void
--
--  NOTES:  	sends a packet to notify the other side that this is the last packet 
--  			in a given set
------------------------------------------------------------------------------*/
"""	
def finPacket(address, protocol, pswd):
	packet = IP(dst=address, id=pswd)
	if protocol == 'tcp':
		proto = TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=15)
	elif protocol == 'udp':
		proto = UDP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), chksum=15)
	elif protocol == 'icmp':
		proto = ICMP(chksum=15)

	send(packet/proto, verbose=0)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   stripPacket(packet, proto)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	stripPacket(packet, proto)
--						packet - the packet to strip
--						proto - the protocol of the packet
--
--  RETURNS: 	ip packet header, protocol specific Header, and packet payload
--
--  NOTES:		strips the packet based on protocol, for ease of use later on.
--  
------------------------------------------------------------------------------*/
"""	
def stripPacket(packet, proto):
	ipLength = 20
	udpLength = 8
	icmpLength = 4
	ethLength = 14
	
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkType(packet)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	checkType(packet)
--					packet - the packet to check the type of 
--
--  RETURNS:  	the protocol of the packet (tcp, udp, icmp)
--
--  NOTES:  	checks the packet type, and returns it
--  
------------------------------------------------------------------------------*/
"""	
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   encrypt(phrase)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	encrypt(phrase)
--					phrase - the message to encrypt
--
--  RETURNS:  	the encrypted phrase (two bytes)
--
--  NOTES:  	encrypts a phrase using a simple encryption scheme, specifically
--  			for this program
------------------------------------------------------------------------------*/
"""	
def encrypt(phrase):
	# can only be two bytes long!
	# get number of characters, take every second one
	# add them together
	# return as int
	total = [0, 0]
	n = 2
	parts = [phrase[i:i+n] for i in range(0, len(phrase), n)]
	for x in parts:
		total[0] += ord(x[0])
		try:
			total[1] += ord(x[1])
		except IndexError:
			total[1] += 99

	return total[0] + total[1]

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   encryptData(data)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	encryptData(data)
--					data - the data to encrypt
--
--  RETURNS:  	string - the encrypted data
--
--  NOTES:  	Uses the knockcode defined in the config file to encrypt the data
--  			then returns it
------------------------------------------------------------------------------*/
"""	
def encryptData(data):
	string = ""
	for c in data:
		string += chr((ord(c) ^ config.knock[0]) % 256)

	return string

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   decryptData(data)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	decryptData(data)
--
--  RETURNS:  	string - the decrypted data
--
--  NOTES:  	uses the knockcode defined in the config file to decrypt the data
--  			then return it
------------------------------------------------------------------------------*/
"""	
def decryptData(data):
	string = ""

	if type(data) is str:
		for c in data:
			string += chr((ord(c) ^ config.knock[0]) % 256)
	else:	
		string += chr((data ^ config.knock[0]) % 256)
	return string
