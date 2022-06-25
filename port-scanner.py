from pprint import pprint
import nmap

commonPorts = {
    7: 'echo',
    20: 'ftp',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    43: 'whois',
    53: 'dns',
    67: 'dhcp',
    68: 'dhcp',
    80: 'http',
    110: 'pop3',
    123: 'ntp',
    137: 'netbios',
    138: 'netbios',
    139: 'netbios',
    143: 'imap4',
    443: 'https',
    513: 'rlogin',
    540: 'uucp',
    554: 'rtsp',
    587: 'smtp',
    873: 'rsync',
    902: 'vmware',
    989: 'ftps',
    990: 'ftps',
    1194: 'openvpn',
    3306: 'mysql',
    5000: 'unpn',
    8080: 'https-proxy',
    8443: 'https-alt'
}

scanner = nmap.PortScanner()

print("Welcome!")

ip_add = input("Please enter the IP or URL you want to scan:")
print("The IP or URL you entered is: ", ip_add)
type(ip_add)

port = input("Please enter the port or port range you want to scan separated by a -: ")
print("The port or port range you entered is: ", port)
type(port)

resp = input(""" \nPlease choose the type of scan you want to perform
                    1) SYN Scan
                    2) UDP Scan
                    3) Comprehensive Scan \n""")

print("You have selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, port, '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    portList = list(scanner[ip_add]['tcp'].keys())
    pprint(portList)
    servList = input("Display ports with common services? y/n ").lower()
    if servList == 'y':
        for i in portList:
            for key, value in commonPorts.items():
                if key == i:
                    print(key, value)
                else:
                    continue
    elif servList == 'n':
        quit


elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, port, '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    portList = list(scanner[ip_add]['udp'].keys())
    pprint(portList)
    servList = input("Display ports with common services? y/n ").lower()
    if servList == 'y':
        for i in portList:
            for key, value in commonPorts.items():
                if key == i:
                    print(key, value)
                else:
                    continue
    elif servList == 'n':
        quit


elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, port, '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    portList = list(scanner[ip_add]['tcp'].keys())
    pprint(portList)
    servList = input("Display ports with common services? y/n ").lower()
    if servList == 'y':
        for i in portList:
            for key, value in commonPorts.items():
                if key == i:
                    print(key, value)
                else:
                    continue
    elif servList == 'n':
        quit


elif resp >= '4':
    print("Please enter a valid option")
