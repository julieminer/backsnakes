import os
import psutil
import random
import setproctitle

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

	