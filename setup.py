import os

os.system("yum install -y python-devel python-pip libpcap* pcapy* scapy* python-inotify htop")
os.system("pip install pcapy psutil setproctitle pyinotify evdev")
