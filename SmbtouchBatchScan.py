# Shadowbrokers leaked tool - Smbtouch batch scanner 
# By Urahara (http://reverse-tcp.xyz)

#Usage: SmbtouchBatchScan.py <start-ip> <end-ip>

import os, re, sys, fileinput, socket

BeginIP = sys.argv[1]
EndIP = sys.argv[2]

socket.inet_aton(BeginIP)
socket.inet_aton(EndIP)
Timeout = 2.0
IPList = []
IPRange = BeginIP[0:BeginIP.rfind('.')]
begin = BeginIP[BeginIP.rfind('.') + 1:]
end = EndIP[EndIP.rfind('.') + 1:]
for i in range(int(begin), int(end)):
    strIP = "%s.%s" % (IPRange, i)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(Timeout)
    address = (strIP, 445)
    try:
        sock.connect(address)
    except:
        sock.close()
    sock.close()
    IPList.append(strIP)

OldIP = '      <value>127.0.0.1</value>'
TempIP = OldIP
for ip in IPList:
    NewIP= '      <value>' + ip + '</value>'
    print '-' * 80
    print '[*] Target: ' + ip
    for line in fileinput.input('Smbtouch-1.1.1.xml',inplace=1):  
    	print line.rstrip().replace(TempIP,NewIP)
    TempIP = NewIP			     
    Output = os.popen(r"Smbtouch-1.1.1.exe").readlines()

    count = 0
    line_start = 0
    line_end = 0
    for count in range(len(Output)):
        if re.search(r'\[\+\] Target OS', Output[count]):
            print Output[count], Output[count+1]     
        if re.search(r'\[Not Supported\]', Output[count]):
            line_start = count
        if re.search(r'\[*\] Writing output parameters', Output[count]):    
            line_end = count - 1
            for line in range(line_start, line_end):
                print Output[line]
else:    
     for line in fileinput.input('Smbtouch-1.1.1.xml',inplace=1):  
     	print line.rstrip().replace(NewIP,OldIP)
