
from scapy.all import *
from scapy.layers import http
import requests
import time
import scapy_ex

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#needed scapy, pcapy,
#needs root
def httpfinder(packet):
    if not packet.haslayer(http.HTTPRequest):
        # This packet doesn't contain an HTTP request so we skip it
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer = packet.getlayer(IP)
    print '\n{0[src]} : {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)


def VendorFind(MACpref):
    f=open("/root/mac_vendor.txt")
    for line in f:
        VendorStuff = line.split("|")
        VendorStuff.append('Moo')
        VendorStuff.append('Moo')
        vendorlong=VendorStuff[2]
        if MACpref==VendorStuff[0]  :
            global vendorname
            vendorname=vendorlong
            
def lengthmaker(string,length):
    lengthstring = (string + '                                          ')
    lengthstring = lengthstring[0:length]
    return lengthstring

def fileWriter(list):
    file1=open('wifilist.txt','w')
    for item in listOfDevices:
        file1.write(item)
    file1.close()
    
            
listOfMACs=[]
listOfDevices=['    \n','     \n','     \n','Axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n']
listOfAPs=[]
clientSubtypes = ('1b',1,4)
def finder(packet):
    if packet.haslayer(Dot11):
        if packet.type==0 and packet.subtype == 8:
            if packet.addr2 not in listOfMACs:
                listOfMACs.append(packet.addr2)
                MACpref = packet.addr2[0:8]
                MACpref=MACpref.upper()
                VendorFind(MACpref)
                listAddition=packet.addr2,packet.info
                listOfAPs.append(listAddition)
                APname=lengthmaker(packet.info,20)
                signalstrength=packet.dBm_AntSignal
                try:
                    
                    global vendorname
                    vendorname=lengthmaker(vendorname[:-2],20)
                    listOfDevices.append("Access Point %s with MAC %s, made by %s,    with strength %s \n" %(APname,packet.addr2,vendorname, signalstrength))
                    listOfDevices.sort()
                    return
                except UnboundGlobalError:
                    listOfDevices.append("Access Point %s with MAC %s, no vendor found \n" %(packet.info,packet.addr2))
                    listOfDevices.sort()

                    return
        if packet.type==0 and packet.subtype == 4:
            if packet.addr2 not in listOfMACs:               
                MACpref = packet.addr2[0:8]
                MACpref=MACpref.upper()
                VendorFind(MACpref)
                APname=lengthmaker(packet.info,10)
                try:
                    global vendorname
                    vendorname=lengthmaker(vendorname[:-2],15)
                    
                    if packet.addr3 == 'ff:ff:ff:ff:ff:ff':
                        listOfDevices.append("Client made by %s : %s, not connected to anything \n" %(vendorname,packet.addr2))
                        listOfDevices.sort()
                        listOfMACs.append(packet.addr2)
                        return
                    elif packet.addr1 in listOfAPs:
                        print'found connected AP'
       
                except UnboundLocalError:
                    vendorname=lengthmaker('Vendor Not Found',20)
                    print "Client made by %s with MAC %s, no vendor found" %(vendorname,packet.addr2)
                    return

        fileWriter(listOfDevices)

    

endtime=time.time()+1
while time.time() < endtime:
    sniff(iface="wlan0mon", prn = finder)

#sniff(iface="at0", prn = httpfinder)

