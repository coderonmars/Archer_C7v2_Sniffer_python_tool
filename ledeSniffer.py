#!/usr/bin/python

#
# import from python
#
import subprocess
import threading
import os
import time

tcpdumpFlag = 0
# 
# This is the python tool that I will contorl Dokota to be sniffer
# I would like to have the whole setup flow and also able to switch chnnanel 
#


#
# Check AP alive before start
#
def checkAPAlive(apip):
    checkFlag = 0 # check the detail after statistics
    ## Ping from local to AP to see if alive
    p = subprocess.Popen(["ping", "-c", "3", apip], stdout=subprocess.PIPE)
    output, err = p.communicate()
    ## Check the ping statistics
    pingRet = output.splitlines()
    if len(pingRet) == 0:
        print "No connection, please check ethernet status"
        return False
    
    for stat in pingRet:
        if checkFlag == 1:
            print stat
            if "errors" in stat:
                print "Ping Fail, please check CONFIG file"
                return False
        if "ping statistics" in stat:
            checkFlag = 1
    return True

#
# Check the AP config from file
# It will return a IP content or empty
#
def getAPIPConfig():
    ret = ""
    if os.path.isfile("CONFIG") != True:
        return ret
    f = open("CONFIG","r")
    fl = f.readlines()
    for ip in fl:
        ip = ip.rstrip('\n')
        if "ap_ip" in ip:
            ret = ip.split(" ")
            ret = ret[1]
            break
    f.close()
    return ret
#
# According to channel to get mapping inferface
#
def getInterface(chnl):
    chanl = int(chnl)
    if chanl < 13 and chanl > 0:
        print "Using wlan1 to config sniffer channel"
        return "radio1"
    elif chanl >= 36:
        print "Using wlan0 to config sniffer channel"
        return "radio0"
    else:
        print "Channel does not support"
        return ""
#
# Generate tcpdump file
#
def genTcpdumpscrpit(sship,interface):
    curDicpipe = os.getcwd()#os.path.dirname(__file__)
    curDicpipe += "/pipe"

    genScrf = open("genTcpdumpScr",'w')
    scrCon = "ssh " + sship + " \"tcpdump -i " + interface + " -s 0 -U -w -\" > " + curDicpipe
    print scrCon
    genScrf.write(scrCon)
    genScrf.close()

#
#  To setup AP mode and channel for sniffer 
#
def setAPConfig(ip , channel, interface):
    # setup mapping interface to monitor mode
    global tcpdumpFlag
    sship = "root@"+ip
    uciCmd = ""

#    if interface == "radio0":
#        uciCmd = "wireless.radio0.channel="+channel
#    else:
#        uciCmd = "wireless.radio1.channel="+channel
#    lp = subprocess.Popen(["ssh", sship, "uci", "set", uciCmd], stdout=subprocess.PIPE)
#    output, err = lp.communicate()
#    print output

    if interface == "radio0":
        uciCmd = "wireless.@wifi-iface[0].mode=monitor"
    elif interface == "radio1":
        uciCmd = "wireless.@wifi-iface[1].mode=monitor"

    lp = subprocess.Popen(["ssh", sship, "uci", "set", uciCmd], stdout=subprocess.PIPE)
    output, err = lp.communicate()
    print output

    lp = subprocess.Popen(["ssh", sship, "uci", "commit", "wireless"], stdout=subprocess.PIPE)
    output, err = lp.communicate()
    print output
    
    # update interface
    if interface == "radio0":
        interface = "wlan0"
    else:
        interface = "wlan1"

    lp = subprocess.Popen(["ssh", sship, "iwconfig", interface, "channel", channel], stdout=subprocess.PIPE)
    output, err = lp.communicate()
    print output

    # set wifi to update config
    lp = subprocess.Popen(["ssh", sship, "wifi"], stdout=subprocess.PIPE)
    # set up flag for sniffer
    output, err = lp.communicate()
    print output
    
    # mkfifo to recieve buffer
    curDicpipe = os.getcwd()#os.path.dirname(__file__)
    curDicpipe += "/pipe"
    lp = subprocess.Popen(["mkfifo", curDicpipe], stdout=subprocess.PIPE)
    output, err = lp.communicate()
    #print output
    # using ssh 
    tcpdumpCmd = "\"tcpdump -i "+ interface + " 3 -s 0 -U -w -\""
    print tcpdumpCmd
    tcpdumpFlag = 1
    curDicpipe = os.getcwd()#os.path.dirname(__file__)
    print curDicpipe
    genTcpdumpscrpit(sship, interface)
    tcpdumpCmd = curDicpipe + "/genTcpdumpScr"
    p = subprocess.Popen(["sh", tcpdumpCmd], stdout=subprocess.PIPE) 
    output, err = p.communicate()

#
# Generate start sniffer script
#
def genSnifferScript():
    curDicpipe = os.getcwd()#os.path.dirname(__file__)
    curDicpipe += "/pipe"

    genScrf = open("genStartSnifferScr",'w')
    scrCon = "sudo wireshark -k -i " + curDicpipe
    print scrCon
    genScrf.write(scrCon)
    genScrf.close()

def startWireShark():
    curDicpipe = os.getcwd()#os.path.dirname(__file__)
    curDicpipe += "/genStartSnifferScr"
    genSnifferScript()
    p = subprocess.Popen(["sh",curDicpipe], stdout=subprocess.PIPE)
    output, err = p.communicate()
    print output

def getRootPWD():
    print "Get Root first for following working"
    p = subprocess.Popen(["sudo","ls"], stdout=subprocess.PIPE)
    output, err = p.communicate()

#
# The main function to control all the flow
#
def main():
    global tcpdumpFlag
    print "##### Get Info to start Dakota Sniffer"
    APIP = getAPIPConfig()
    if len(APIP) > 0 :
        print "##### Get AP IP from Config " + APIP
    else :
        print "Target sniffer AP not found"
        return
 
    print "##### Get Root for following command"
    getRootPWD()
    
    print "##### Check if AP alive"
    if checkAPAlive(APIP) == False:
        return
    
    print "##### With Archer_C7v2_Sniffer_imag, no need to check tools"

    print "##### Please set the sniffer channel:"
    chnl = raw_input("Please set the sniffer channel: \n")
    SnifferInterface = getInterface(chnl)
    if SnifferInterface == "":
        return

    print "##### kick off a thread to setup mode & channel & tcpdump on Sniffer AP"
    ## To setup mode & channel on Sniffer AP
    threadObj = threading.Thread(target=setAPConfig, args=(APIP, chnl,SnifferInterface))
    threadObj.start()

    print "##### Start enable wireshark until tcpdump working"
    while tcpdumpFlag == 0:
        print "Waiting tcpdump setting"
        time.sleep(3)

    print "##### kick off a thread to start wireshark for packet parsing"
    ## To setup mode & channel on Sniffer AP
    threadObj2 = threading.Thread(target=startWireShark, args=())
    threadObj2.start()

    time.sleep(3)

    print "##### Run Ctrl + C for stop all function at this version"
    
if __name__ == "__main__":
    main()
