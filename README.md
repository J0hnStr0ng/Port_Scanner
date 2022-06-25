# **Simple Parameter Port Scanner**

## **Parameters**
* IP address of target machine
* Port or port range you would like to scan ex. 1 or 1-1024
* Scan type
* Common port service listing

## **Scan Types**
* SYN scan using the -sS flag
* UDP scan using the -sU flag
* Comprehensive scan using the -sS -sV -sC -A -O flags

## **Flag Descriptions**
* -sS: TCP SYN port scan
* -sU: UDP port scan
* -sV: Attempts to determine the service version running on the port
* -sC: Scans with default NSE scripts for disovery purposes
* -A: Enables OS detection, version detection, script scanning, and traceroute
* -O: Remote OS detection using TCP/IP stack fingerprinting
