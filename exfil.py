import pyinotify
import threading

client = ""


class EventHandler(pyinotify.ProcessEvent):
	def process_IN_CREATE(self, event):
		print "Created: ", event.pathname

	def process_IN_DELETE(self, event):
		print "Deleted: ", event.pathname

mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE
handler = EventHandler()
wama = pyinotify.WatchManager()
noti = pyinotify.Notifier(wama, handler)

def addWatch(target):
	# print target# check if positive for success
	if (wama.add_watch(target, mask, rec=True) > 0):
		print "added: " + target

def removeWatch(target):
	# print target # check if True on success
	if (wama.rm_watch(wama.get_wd(target))):
		print "removed: " + target

def sendFile(target):
	print target

def exfilThread():
	noti.loop()

def startThread(): # address, protocol, password):
	listenThread = threading.Thread(target=exfilThread) #, args=(address, protocol, password))
	listenThread.daemon = True
	listenThread.start()