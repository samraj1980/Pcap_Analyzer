from scapy.all import *
from scapy.layers.inet import IP, Ether, ARP, Dot3, UDP
#from datetime import *
#from django.core.files.storage import FileSystemStorage
#from fileinput import close

def analyzepcap(pcap_file):


# list1 of common IP protocols
    IPProtocols = {
    0: 'IP', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-ENCAP', 56: 'TLSP', 133: 'FC', 6: 'TCP', 8: 'EGP', 137: 'MPLS-IN-IP',
    138: 'MANET', 139: 'HIP', 12: 'PUP', 17: 'UDP', 20: 'HMP', 22: 'XNS-IDP', 132: 'SCTP', 27: 'RDP', 29: 'ISO-TP4',
    5: 'ST', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 41: 'IPV6', 43: 'IPV6-ROUTE', 44: 'IPV6-FRAG', 45: 'IDRP',
    46: 'RSVP', 47: 'GRE', 136: 'UDPLITE', 50: 'IPSEC-ESP', 51: 'IPSEC-AH', 9: 'IGP', 57: 'SKIP', 58: 'IPV6-ICMP',
    59: 'IPV6-NONXT', 60: 'IPV6-OPTS', 73: 'RSPF', 81: 'VMTP', 88: 'EIGRP', 89: 'OSPFIGP', 93: 'AX.25', 94: 'IPIP',
    97: 'ETHERIP', 98: 'ENCAP', 103: 'PIM', 108: 'IPCOMP', 112: 'VRRP', 115: 'L2TP', 124: 'ISIS'
     }
#print('6' in IPProtocols.values())
#print(IPProtocols[6])
#True
# list1 of common TCP port numbers to find out running services

    TCPPorts = {
    20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 389: 'LDAP', 636: 'LDAPssl',
    137: 'NetBIOS Name Service NBNS', 138: "NetBios Datagram Service NBDS", 520: 'RIP', 161: 'SNMP', 179: 'BGP',
    445: 'SMB', 67: 'DHCP Bootpc', 68: 'DHCP Bootps', 49: 'TACACS', 88: 'Kerberos', 156: 'SQL Service', 162: 'SNMP Trap',
    530: 'RPC', 5060: 'SIP non encrypted', 5061: 'SIP encrypted'
    }


    out_file = '/home/samraj1980/Pcap_Analyzer/media/pcapfile-%s.csv'%datetime.now().strftime('%Y-%m-%d_%H_%M')

    #fs = FileSystemStorage()
    #filename = fs.save(out_file)

    #print filename
    # Create a file and add date and time to it
    # Replace the file extnesion .csv to any that you want . for example ->   .txt
    #filename = 'C:/Users/sarve/Desktop/pcaps/pcapfile-%s.txt'%datetime.now().strftime('%Y-%m-%d_%H_%M')

    f1 = open(out_file, 'w+')
#    f1.close()


#    print out_file

    pcap_file =  '/home/samraj1980/Pcap_Analyzer' + pcap_file
    print pcap_file
#    print pcap_file

    try:
        #Read a pcap file and store it in variable a
        a = rdpcap(pcap_file)

    except Exception as e:
        print('Something went wrong while opening/reading the pcap file.' '\n\nThe error message is: %s' % e)
        exit(0)

    # X denotes the packet number. Initially we will start with first packet denoted by 0.
    x = 0
    # Go through each packet and increment value of X after the loop

    while x < len(a):
        # Approach is to write a safe code
        # Hence value checking is done at every step using if statement
        #raw_packet = str(a[x].show())
        raw_packet = str(a[x].summary())

        if raw_packet.count("IP") > 0:
            # IPV6 packet format is different from IPv4. Hence the below techniques to extract packet information wont work
            # Hence I filtered IPv6
            #IPvar = (str(re.findall('\\bIPv6\\b', raw_packet)))

            raw_packet = str(a[x].command())

            if raw_packet.count("IPv6") > 0:
                pass
            else:
                #raw_packet = str(a[x].command())
                #print(raw_packet)

                if raw_packet.count("proto") > 0:
                    IPnum = a[x][IP].proto
                    #print(IPnum)
                # All the packet information will be stored in the list1
                list1 = []

                list1.append("| PACKET " + str(x + 1) + " |,   ")

                if raw_packet.count("src") > 0:
                    #print(raw_packet)
                    list1.append("Source IP: " + str(a[x][IP].src) + " ,   ")
                if raw_packet.count("dst") > 0:
                    list1.append("Destination IP: " + str(a[x][IP].dst) + " ,   ")

                # IP protocol information is available in the dictionary. it will lookup to find right protocol information
                # 'one' in d.values() True
                # If IP Protocol is not available then it will throw an exception.
                # Hence check whether value exists in dictionary
                _dict_value = IPnum in IPProtocols.keys()
                #print(_dict_value)
                if _dict_value is True:
                    list1.append("Protocol: " + str(IPProtocols[IPnum]) + " ,   ")

                if raw_packet.count("dst") > 0:
                    list1.append("Dest MAC: " + str(a[x][Ether].dst) + " ,   ")

                if raw_packet.count("src") > 0:
                    list1.append("Src MAC: " + str(a[x][Ether].src) + " ,   ")

                if raw_packet.count("version") > 0:
                    list1.append("IP version: " + str(a[x][IP].version) + ",    ")

                # Few packets does not have source and destinationport numbers. Hence we check it here before calculating.
                # Else it will trigger an error
                if raw_packet.count("sport") > 0:
                    list1.append("Source Port: " + str(a[x][IP].sport) + ",    ")
                    port_info = a[x][IP].sport
                    #print(p)
                    # Port number information is available in the dictionary.
                    # It will lookup to find right service information
                    # Check whether value exists in dictionary
                    _dict_value = port_info in TCPPorts.keys()
                    #print(_dict_value)
                    if _dict_value is True:
                        list1.append(str(TCPPorts[port_info]) + " service is running,    ")

                if raw_packet.count("dport") > 0:
                    list1.append("Destination Port: " + str(a[x][IP].dport) + "  ,  ")
                    port_info = a[x][IP].dport
                    # Port number information is available in the dictionary.
                    # It will lookup to find right service information
                    # Check whether value exists in dictionary
                    _dict_value = port_info in TCPPorts.keys()
                    #print(_dict_value)
                    if _dict_value is True:
                        list1.append(str(TCPPorts[port_info]) + " service is running,    ")

                # Calculate the TTL
                list1.append("TTL: " + str(a[x][IP].ttl) + " ,   ")

                if raw_packet.count("Mac OS X") > 0:
                    n = raw_packet.find("Mac OS X")
                    m = n + 17
                    version = raw_packet[n:m]
                    list1.append("Operating System Details- Name: MAC OS X,  MAC Operating Version: " + version  + " ,   ")

                if raw_packet.count("Windows") > 0:
                    n = raw_packet.find("USER-AGENT")
                    m = raw_packet.find("\n")
                    Details = raw_packet[n:m]
                    list1.append("Details: " + Details + "Windows Operating system,     ")

                n = raw_packet.find("CDP")
                if n > 0:
                    list1.append("CDP is used by the CISCO device,   ")

                # list1 displays in an array format. Hence we join to remove unrequired characters
                modifylist1 = ''.join(list1)
#                print(modifylist1)
                f1.write(modifylist1)
                f1.write("\n")
                f1.write("\n")

        # Router communication involves sending ARP request
        if raw_packet.count("ARP") > 0:
            raw_packet = str(a[x].command())
            # print(raw_packet)
            # All the packet information will be stored in the list1
            list1 = []
            list1.append("| PACKET " + str(x + 1) + " |,  ")
            try:
                n = raw_packet.find("ARP")
                m = raw_packet.find("op=2")
                o = raw_packet.find("Padding")
                if n > 0 and m > 0 and o > 0:
                    list1.append("Mac address of router: " + str(a[x][ARP].hwsrc) + ",    ")
                    list1.append("IP address of router: " + str(a[x][ARP].psrc) + " ,   ")

            except Exception as e:
                print("")

            # Checking for SNMP manager and its details
            if raw_packet.find("SNMP") > 0:
                prot = str(a[x][UDP].dport)
                if prot == "161":
                    list1.append("SNMP Manager details " + str(a[x][IP].src) + str(a[x][IP].dst) + " ,   ")

            # list1 displays in an array format. Hence we join to remove unrequired characters
            modifylist1 = ''.join(list1)
#            print(modifylist1)
            f1.write(modifylist1)
            f1.write("\n")
            f1.write("\n")

        # Login to idenitfy if there are Cisco Network Switch in the pcap file

        raw_packet = str(a[x].command())
        if raw_packet.count("Cisco") > 0:
            v = str(a[x][Raw].command())
            s = str(a[x][Raw].command())
            # print(raw_packet)
            # All the packet information will be stored in the list1
            list1 = []
            list1.append("| PACKET " + str(x + 1) + " | ,  ")
            n = v.find("Cisco")
            data = v[n:]
            list1.append(data + ",    ")
            if s.count("Switch") > 0:
                list1.append("   The device is a SWITCH,   ")
            list1.append("MAC address of Device: " + str(a[x][Dot3].src)  + ",    ")

            # list1 displays in an array format. Hence we join to remove unrequired characters
            modifylist1 = ''.join(list1)
#            print(modifylist1)
            f1.write(modifylist1)
            f1.write("\n")
            f1.write("\n")
        #Move to next packet
        x += 1

    f1.close()

    out_file = out_file.split("Pcap_Analyzer/",1)[1]
    return  out_file

if __name__ == '__main__':

    try:
        pcap_file = sys.argv[1]
    except IndexError:
        pcap_file = None


    total_packets = analyzepcap(pcap_file)
