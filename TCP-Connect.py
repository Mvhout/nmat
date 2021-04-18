from socket import *
import time
startTime = time.time()

print("Toets hieronder de website in welke u gescand wilt hebben zonder http(s):// \n")
print("Bijvoorbeeld: \n\n google.nl \n spele.nl \n scanme.nmap.org \n")

if __name__ == "__main__":
   target = str(input("Vul hier de website in: \n"))
   t_IP = gethostbyname(target)
   print("\nVul hieronder uw begin en eind port in. \nWilt u 1 port scannen, gebruik 1 port hoger bij uw eindport \n")
   print("Voorbeeld:\n\n2 porten: \nBegin port 80\nEindport 200\n\n1 port:\nBegin port 80\nEind port 81\n")
   port_a = int(input("Vul uw begin port in om te scannen: "))
   port_b = int(input("Vul uw eind port in om te scannen: "))
   print (f"\nStart scan op host: {target} \nop IP adres: {t_IP}\n")
   
   for i in range(port_a, port_b + 1):
      s = socket(AF_INET, SOCK_STREAM)
     
      conn = s.connect_ex((t_IP, i))
      if(conn == 0) :
        print ('Port %d: OPEN' % (i,))
      elif(conn != 1):
      	print ('Port %d: DICHT' % (i,))
      s.close()

tijd = time.time() - startTime
print(f"\nHet duurde: {tijd} seconden om deze website te scannen")