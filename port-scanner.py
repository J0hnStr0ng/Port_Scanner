import nmap

scanner = nmap.PortScanner()

print("Welcome!")

ip_add = input("Please enter the IP or URL you want to scan:")
print("The IP or URL you entered is: ", ip_add)
type(ip_add)

resp = input(""" \nPlease choose the type of scan you want to perform
                    1) SYN/ACK Scan
                    2) UDP Scan
                    3) Comprehensive Scan \n""")

print("You have selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("Open Ports: ", scanner[ip_add]['tcp'].keys())

elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("Open Ports: ", scanner[ip_add]['udp'].keys())

elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_add, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_add].state())
    print(scanner[ip_add].all_protocols())
    print("Open Ports: ", scanner[ip_add]['tcp'].keys())

elif respo >= '4':
    print("Please enter a valid option")