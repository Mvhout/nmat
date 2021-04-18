import pyfiglet

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

# TCP-connect scan
if scan == "1":
	print("1")
# TCP-SYN scan
if scan == "2":
	print("2")
# UDP scan
if scan == "3":
	print("3")
# XMAS scan
if scan == "4":
	print ("4")


#Vul een target in (127.0.0.1)
#host = input("Vul Het IP adres of de website van uw target in: ")

#Vul port range in (van 1 t/m 600)
#port_a = int(input("Vul uw begin port in: "))
#port_b = int(input("Vul uw eind port in: "))


# TCP-Connect scan  syn-ack



# TCP-SYN scan  
# UDP scan
# XMAS scan
# SQLI-lite database
