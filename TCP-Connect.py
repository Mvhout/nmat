import socket
import threading
import concurrent.futures

print_lock = threading.Lock()

ip = input("Toets hier uw website in: ")
porta = int(input("Toets hier uw begin port in: "))
portb = int(input("Toets hier uw eind port in: "))

while porta > 65536 or portb > 65536 or porta < 1 or portb < 1 or porta > portb:
   if porta > portb:
      print("Zorg dat uw begin port kleiner is dan uw eind port.")
      porta = int(input("Toets hier uw begin port in: "))
      portb = int(input("Toets hier uw eind port in: "))
   else:
      print("Geen bestaande port of, probeer opnieuw (kies een port tussen 1-65536)")
      porta = int(input("Toets hier uw begin port in: "))
      portb = int(input("Toets hier uw eind port in: "))

openp = []
geslotenp = []

#scan/socket
def scan(ip,port):
   scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   scanner.settimeout(1)

#Open/Gesloten ports
   try:
      scanner.connect((ip,port))
      scanner.close()
      print(f"{port} is Open")
      openp.append(port)

   except:
      geslotenp.append(port)
      pass

#Threading
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executer:
   for port in range(porta,portb + 1):
      executer.submit(scan,ip,port)
