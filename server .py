import socket
from scapy.all import send,IP,TCP,ICMP,UDP
# A UDP server

# Set up a UDP server
UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

# Listen on port 21567
# (to all IP addresses on this system)
listen_addr = ("",5000)
UDPSock.bind(listen_addr)

# Report on all data packets received and
# where they came from in each case (as this is
# UDP, each may be from a different source and it's
# up to the server to sort this out!)
newvar = 0
d={}
while True:
        data,addr = UDPSock.recvfrom(1024)
        #print data.strip()
        var = data.strip()
        #var1 = var-newvar
        var1,eth,dst = var.split(",")
        print var1
        print (eth,"--->",dst)

        if (eth,dst) in d:
            value= d[eth,dst]
            var2= int(var1)
            d[eth,dst]=var2
            if((var2-value)>5):
                print("diff is",(var2-value))
                print("Intrusion Detected")
                Packet=IP(dst="10.0.1.5")/ICMP()/"Intrusion Detected"
                send(Packet)
                Packet.show()
                print("sent")
            
        else:
            d[eth,dst]=int(var1)

