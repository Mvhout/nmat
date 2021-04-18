from scapy.all import *

target = input("Vul hier het de website van uw target in: ")
ip = socket.gethostbyname(target)
src_port = RandShort()
porta = int(input("Vul hier uw start port in: "))
portb = int(input("Vul hier uw eind port in: "))

for x in range(porta,portb + 1):
    print(f"scanning port: {x}")
    stealth_scan_resp = sr1(IP(dst=ip)/TCP(sport=src_port,dport=x,flags="S"),timeout=10)
    if(str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
        print(f"{x} is Filtered")
    elif stealth_scan_resp and stealth_scan_resp.haslayer(TCP) and stealth_scan_resp.getlayer(TCP).flags == 0x12:
        send_rst = sr(IP(dst=x)/TCP(sport=src_port,dport=x,flags="R"),timeout=10)
        print(f"{x} is Open")
    elif stealth_scan_resp and stealth_scan_resp.haslayer(TCP) and stealth_scan_resp.getlayer(TCP).flags == 0x14:
        print(f"{x} is Closed")
    elif stealth_scan_resp and int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13] and stealth_scan_resp.haslayer(ICMP):
        print(f"{x} is filtered")