import pyfiglet
import socket
import threading
import concurrent.futures
import json
import sqlite3
import csv
import pandas as pd

openp = []
geslotenp = []
filteredp = []


#https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
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
# Orderen poorten
openp.sort()
geslotenp.sort()

# TCP-SYN scan
if scan == "2":
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

# UDP scan
if scan == "3":
	print("3")
# XMAS scan
if scan == "4":
	print ("4")
