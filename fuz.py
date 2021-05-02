from scapy.all import *
import os
import time

#works only on linux
#read from filename the logs about the ssh traffic
def read_log(filename):
    error_count = 0
    max_count = 5   #max tolorated errors
    line_count = 10 #read this number of lines
    sshd = "sshd["  #sshd protocol header in logs
    errors = ["Failed password", "invalid user", "error:"]   #errors' identifier
    with open(filename) as f:
        i = 0
        #read from bottom lines and check for abnormality
        for line in reversed(list(f)):
            check = line.rstrip()
            for error in errors:
                if sshd in check and error in check:   #count errors in relevant lines
                    error_count += 1
            i += 1
            if i >= line_count:    #check if read line_count lines
                break
    return not (error_count >= max_count)
        
#detect if there is fuzzing to port 22
def dectector():
    filename = "/var/log/auth.log"   #log file with info on ssh traffic (if there is traffic)
    sleep_time = 1   #sleep time to refresh logs file
    search = True    #search flag, on when searching for fuzzing
    while search:
        pkt = sniff(filter = "dst port 22", count=1)   
        time.sleep(sleep_time)   #sleep to allow the log to refresh
        search = read_log(filename)   #check if to continue searching
    print("Fuzzing detected")

detector()
	

	
