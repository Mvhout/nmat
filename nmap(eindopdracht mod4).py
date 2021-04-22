import pyfiglet
import socket
import threading
import concurrent.futures
import json
import sqlite3
import csv
import pandas as pd
import sys
import subprocess
from scapy.all import *


openp = []
geslotenp = []
filteredp = []

print("=====================================================")
ascii_banner = pyfiglet.figlet_format("Nmat")		
print(ascii_banner)	
print("A netwerkscanner by M. van Hout")								
print("=====================================================")

# Wat voor scan
print ("U kunt kiezen uit 4 verschillende scans: ")
print ("\n 1. TCP-Connect \n 2. TCP-SYN \n 3. UDP \n 4. XMAS \n" )
print ("Type het nummer in voor de scan die u wilt uitvoeren \n")

scan = 0
while scan != "1" and scan != "2" and scan != "3" and scan != "4":
    scan = input("Vul uw keuze in: ")

# Gebruiker input
ip = input("Toets hier uw website in: ")
porta = int(input("Toets hier uw begin port in: "))
portb = int(input("Toets hier uw eind port in: "))

# Portcheck
def portcheck(porta,portb):
   while porta > 65536 or portb > 65536 or porta < 1 or portb < 1 or porta > portb:
      if porta > portb:
         print("Zorg dat uw begin port kleiner is dan uw eind port.")
         porta = int(input("Toets hier uw begin port in: "))
         portb = int(input("Toets hier uw eind port in: "))
      else:
         print("Geen bestaande port of probeer opnieuw (kies een port tussen 1-65536)")
         porta = int(input("Toets hier uw begin port in: "))
         portb = int(input("Toets hier uw eind port in: "))
portcheck(porta,portb)

# TCP-connect scan
if scan == "1":
    print_lock = threading.Lock()
    # scan/socket
    def scan(ip, port):
        scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scanner.settimeout(1)

        # Open/Gesloten ports + wegschrijven naar list
        try:
            scanner.connect((ip, port))
            scanner.close()
            openp.append(port)
            print(f"{port} is Open")
        except:
            geslotenp.append(port)
            pass

    # Threading
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executer:
        for x in range(porta, portb + 1):
            executer.submit(scan, ip, x)

openp.sort()			#Poorten worden door elkaar in de lijst opgeslagen, vandaar dat ik ze hier order.
geslotenp.sort()

# TCP-SYN scan
if scan == "2":
	def scan():
		for x in range(porta, portb + 1):
			print(f"Scanning port {x}:")
			stealth_scan_resp = sr1(IP(dst=ip) / TCP(sport=x, dport=x, flags="S"), timeout=10, verbose=False)
			if (stealth_scan_resp and stealth_scan_resp.haslayer(TCP)):
				if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=ip) / TCP(sport=x, dport=x, flags="R"), timeout=10, verbose=False)
					print(f"port {x} is Open")
					openp.append(x)
			else:
				geslotenp.append(x)
				print(f"port {x} is Dicht")
	scan()

# UDP scan
if scan == "3":
    def getServiceName(port, proto):
        try:
            name = socket.getservbyport(int(port), proto)
        except:
            return None
        return name

    try:
        ip = socket.gethostbyname(ip)
    except:
        print("Deze Website bestaat niet.")
        sys.exit()

    def scan():
        for x in range(porta, portb + 1):
            MESSAGE = "ping"
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if client == -1:
                print("udp socket creation failed")
            sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            if sock1 == -1:
                print("icmp socket creation failed")
            try:
                client.sendto(MESSAGE.encode('utf_8'), (ip, x))
                sock1.settimeout(1)
                data, addr = sock1.recvfrom(1024)
            except socket.timeout:
                serv = getServiceName(x, 'udp')
                if not serv:
                    geslotenp.append(x)
                    print(f"Port {x}: Closed")
                else:
                    filteredp.append(x)
                    print(f"Port {x}: Open | Filtered")

            except socket.error as sock_err:
                if (sock_err.errno == socket.errno.ECONNREFUSED):
                    print(sock_err("Connection refused"))
                client.close()
                sock1.close()
    scan()

# XMAS scan
if scan == "4":
	for x in range(porta, portb + 1):
		xmas_scan_resp = sr1(IP(dst=ip) / TCP(dport=x, flags="FPU"), timeout=5, verbose=False)
		if (str(type(xmas_scan_resp)) == "<type 'NoneType'>"):
			filteredp.append(x)
			print("Open|Filtered")
		elif (xmas_scan_resp and xmas_scan_resp.haslayer(TCP)):
			if (xmas_scan_resp and xmas_scan_resp.getlayer(TCP).flags == 0x14):
				geslotenp.append(x)
				print("Closed")
		elif (xmas_scan_resp and xmas_scan_resp.haslayer(ICMP)):
			if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9,
																											 10, 13]):
				filteredp.append(x)
				print("Filtered")
		else:
			filteredp.append(x)
			print("Port Open | Filtered")

# Wegschrijven XML/JSON

def wegschrijven():
   wegschrijven = input("Wilt u de resultaten van de scan wegschrijven naar een JSON of XML bestand?(j/n): ")
   if wegschrijven == "j" or wegschrijven == "J":
      print("1. XML\n2. JSON")
      keuze = input("Naar wat wilt u de resultaten wegschrijven? (1/2): ")

      #Naar XML schrijven
      if keuze == "1":
         opslaan = input("Hoe wilt u het bestand noemen?: ") + ".xml"
         import xml.etree.cElementTree as ET

         root = ET.Element("root")
         doc = ET.SubElement(root, "doc")

         ET.SubElement(doc, "field1", name="Target").text = ip
         ET.SubElement(doc, "field2", name="Typescan").text = scan
         ET.SubElement(doc, "field3", name="Open").text = str(openp)
         ET.SubElement(doc, "field4", name="Gesloten").text = str(geslotenp)
         ET.SubElement(doc, "field5", name="Filtered").text = str(filteredp)

         tree = ET.ElementTree(root)
         tree.write(opslaan)

      #Naar Json schrijven
      elif keuze == "2":
         opslaan = input("Hoe wilt u het bestand noemen?: ") + ".Json"
         print("De gegevens worden naar een Json bestand geschreven.")
         json_data_scan = {"Target": ip,
                           "Scantype": scan,
                           "Open" : openp ,
                           "Dicht" : geslotenp,
                           "Filtered" : filteredp,
                        }
         with open(opslaan, 'w') as f:
            json.dump(json_data_scan, f)

      else:
         print("Dit is geen geldige keuze.")
   else:
      print("Oke, bedankt voor het gebruiken van deze scanner.")
wegschrijven()