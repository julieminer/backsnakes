from struct import *
from scapy.all import *

def checksum():
	print "checksum"
	
def resolveHost():
	print "resolveHost"
	
def GetIPAddress():
	print "GetIPAddress"
	
def usage():
	print "usage"
	
def XOR():
	print "XOR"
	
def length():
	print "length"

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

def finPacket(address, protocol, pswd):
	packet = IP(dst=address, id=pswd)
	if protocol == 'tcp':
		proto = TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=15)
	elif protocol == 'udp':
		proto = UDP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), chksum=15)
	elif protocol == 'icmp':
		proto = ICMP(chksum=15)

	send(packet/proto, verbose=0)

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

def encryptData(data):
	print "encrypt " + data
	return data

def decryptData(data):
	print "decrypt " + data