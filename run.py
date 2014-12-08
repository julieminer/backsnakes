from subprocess import Popen, PIPE
import os

results = Popen("pwd", shell=True, stdout=PIPE).stdout.read()
results = "nohup python " + results[:-1] + "/backjake.py &"
os.system(results)
