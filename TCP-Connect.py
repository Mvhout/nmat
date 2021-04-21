import socket
import threading
import concurrent.futures

print_lock = threading.Lock()

ip = input("Toets hier uw website in: ")
porta = int(input("Toets hier uw begin port in: "))
portb = int(input("Toets hier uw eind port in: "))

def scan(ip,port):
   scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   scanner.settimeout(1)
   try:
      scanner.connect((ip,port))
      scanner.close()
      print(f"{port} Open")
   except:
      pass

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executer:
   for port in range(porta,portb + 1):
      executer.submit(scan,ip,port)