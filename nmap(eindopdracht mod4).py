import pyfiglet
import socket
from scapy.all import *
import threading
import concurrent.futures
import json
import sqlite3
import csv
import pandas as pd
import sys
import subprocess
import xml.etree.cElementTree as ET


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

scantype = 0
while scantype != "1" and scantype != "2" and scantype != "3" and scantype != "4":
    scantype = input("Vul uw keuze in: ")

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
if scantype == "1":
    scantype = "TCP-Connect"
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
if scantype == "2":
    scantype = "TCP-SYN"
    def scan():
        for x in range(porta, portb + 1):
            stealth_scan_resp = sr1(IP(dst=ip) / TCP(sport=x, dport=x, flags="S"), timeout=10, verbose=False)
            if (stealth_scan_resp and stealth_scan_resp.haslayer(TCP)):
                if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=ip) / TCP(sport=x, dport=x, flags="R"), timeout=10, verbose=False)
                    print(f"port {x}: Open")
                    openp.append(x)
            else:
                geslotenp.append(x)
                print(f"port {x}: Dicht")
    scan()

# UDP scan
if scantype == "3":
    scantype = "UDP scan"
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
                    print(f"Port {x}: Dicht")
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
if scantype == "4":
    scantype = "XMAS scan"
    for x in range(porta, portb + 1):
        xmas_scan_resp = sr1(IP(dst=ip) / TCP(dport=x, flags="FPU"), timeout=5, verbose=False)
        if (str(type(xmas_scan_resp)) == "<type 'NoneType'>"):
            filteredp.append(x)
            print("Open|Filtered")
        elif (xmas_scan_resp and xmas_scan_resp.haslayer(TCP)):
            if (xmas_scan_resp and xmas_scan_resp.getlayer(TCP).flags == 0x14):
                geslotenp.append(x)
                print(f" Port {x}: Dicht")
        elif (xmas_scan_resp and xmas_scan_resp.haslayer(ICMP)):
            if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9,
                                                                                                             10, 13]):
                filteredp.append(x)
                print(f" Port {x}: Filtered")
        else:
            filteredp.append(x)
            print(f"Port {x}: Open | Filtered")


#Wegschrijven database

conn = sqlite3.connect("scan_resultaten.db")

c = conn.cursor()

#Maakt tables aan in database
c.execute("""CREATE TABLE IF NOT EXISTS target (
            target text)""")
c.execute("""CREATE TABLE IF NOT EXISTS scantype (
            type_scan text)""")
c.execute("""CREATE TABLE IF NOT EXISTS portrange (
            begin integer,eind INTEGER)""")
c.execute("""CREATE TABLE IF NOT EXISTS open (
            open_port INTEGER)""")
c.execute("""CREATE TABLE IF NOT EXISTS gesloten (
            gesloten_port INTEGER)""")
c.execute("""CREATE TABLE IF NOT EXISTS filtered (
            filtered_port INTEGER)""")

dbopen = [(o,) for o in openp]
dbgesloten =[(g,) for g in geslotenp]
dbfiltered = [(f,) for f in filteredp]

#Voegt de data in de database
c.execute('INSERT INTO target VALUES(?)',(ip,))
c.execute('INSERT INTO scantype VALUES(?)',(scantype,))
c.execute("INSERT INTO portrange VALUES(?,?)",(porta,portb,))
c.executemany("INSERT INTO open VALUES(?)",(dbopen))
c.executemany("INSERT INTO gesloten VALUES(?)",(dbgesloten))
c.executemany("INSERT INTO filtered VALUES(?)",(dbfiltered))
conn.commit()

conn.close()

#geprobeerd middels een ERD een goed werkende datbase te maken, dit is niet gelukt.

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
         ET.SubElement(doc, "field2", name="Typescan").text = scantype
         ET.SubElement(doc, "field3", name="Port Range").text = f"{porta}-{portb}"
         ET.SubElement(doc, "field4", name="Open").text = str(openp)
         ET.SubElement(doc, "field5", name="Gesloten").text = str(geslotenp)
         ET.SubElement(doc, "field6", name="Filtered").text = str(filteredp)

         tree = ET.ElementTree(root)
         tree.write(opslaan)

      #Naar Json schrijven
      elif keuze == "2":
          opslaan = input("Hoe wilt u het bestand noemen?: ") + ".json"
          print("De gegevens worden naar een Json bestand geschreven.")
          json_data_scan = {"Target": ip,
                            "Scantype": scantype,
                            "Port Range" : f"{porta}-{portb}",
                            "Open": openp,
                            "Dicht": geslotenp,
                            "Filtered": filteredp
                            }
          with open(opslaan, 'w') as f:
              json.dump(json_data_scan, f)

      else:
         print("Dit is geen geldige keuze.")
   else:
      print("Oke, bedankt voor het gebruiken van deze scanner.")
wegschrijven()