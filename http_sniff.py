from scapy.all import sniff, TCP, Raw

def show(pkt): 
    if pkt.haslayer("TCP") and pkt.haslayer("Raw") and pkt[TCP].dport == 80:
        print(pkt[Raw].load.decode(errors="ignore"))
        print("-----")
        print("Packet Summary:")
        print(pkt.summary())
        print("\n")



try:
    print("start sniffing...")
    sniff(iface="Wi-Fi", filter="tcp", prn=show)
except KeyboardInterrupt:
    print("\nSniffing stopped by user.")