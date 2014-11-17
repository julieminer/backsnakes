def checksum():
	print "checksum"
	
def resolveHost():
	print "resolveHost"
	
def GetIPAddress():
	print "GetIPAddress"
	
def usage():
	print "usage"
	
def XOR():
	print "XOR"
	
def length():
	print "length"

def encrypt(phrase):
	# can only be two bytes long!
	# get number of characters, take every second one
	# add them together
	# return as int
	total = [0, 0]
	n = 2
	parts = [phrase[i:i+n] for i in range(0, len(phrase), n)]
	for x in parts:
		total[0] += ord(x[0])
		try:
			total[1] += ord(x[1])
		except IndexError:
			total[1] += 99

	return total[0] + total[1]

def encryptData(data):
	print "encrypt" + data

def decryptData(data):
	print "decrypt " + data