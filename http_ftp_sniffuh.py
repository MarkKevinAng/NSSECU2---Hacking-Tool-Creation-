from scapy.all import sniff, TCP, Raw, IP
from datetime import datetime
from urllib.parse import parse_qs
import os

# --- Global Lists for Storing Credentials ---
ftp_credentials = []
http_credentials = []

# --- FTP Analysis Functions ---

def analyze_ftp_packet(pkt):
    """Callback function to process packets for FTP credentials."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 21: # dport == 21 means FTP port
        try:
            data = pkt[Raw].load.decode('utf-8', errors="ignore")
            # FTP commands are separated by \r\n
            lines = data.strip().split('\r\n')
            for line in lines:
                if line.upper().startswith('USER ') or line.upper().startswith('PASS '):
                    credential_type = "Username" if line.upper().startswith('USER ') else "Password"
                    value = line[5:].strip()
                    
                    credential_info = {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "protocol": "FTP",
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "src_port": pkt[TCP].sport,
                        "type": credential_type,
                        "value": value
                    }
                    ftp_credentials.append(credential_info)
                    print(f"[*] FTP {credential_type} Found: {value} ({pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst})")
        except Exception:
            pass # Ignore packets that can't be decoded

# --- HTTP Analysis Functions ---

def analyze_http_packet(pkt):
    """Callback function to process packets for HTTP credentials."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 80:
        try:
            data = pkt[Raw].load.decode('utf-8', errors='ignore')
            # Check for POST requests, common for login forms
            if data.startswith("POST"):
                # Common credential keywords in POST data
                keywords = ['name','uname', 'pass', 'pwd', 'login', 'email', 'username', 'password']
                
                # The body of the POST request is after the double newline
                if '\r\n\r\n' in data:
                    body = data.split('\r\n\r\n', 1)[1]
                    # The parse_qs function correctly parses URL-encoded form data
                    parsed_data = parse_qs(body)
                    
                    for key, value in parsed_data.items():
                        if any(keyword in key.lower() for keyword in keywords):
                            credential_info = {
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "protocol": "HTTP",
                                "src_ip": pkt[IP].src,
                                "dst_ip": pkt[IP].dst,
                                "src_port": pkt[TCP].sport,
                                "type": key,
                                "value": value[0] # parse_qs returns a list
                            }
                            http_credentials.append(credential_info)
                            print(f"[*] HTTP Credential Found: {key} = {value[0]} ({pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst})")
        except Exception:
            pass # Ignore malformed packets

# --- Reporting and Logging Functions ---

def print_summary():
    """Prints a final summary of all captured credentials."""
    print("\n" + "="*25 + " CAPTURE SUMMARY " + "="*25)
    if not ftp_credentials and not http_credentials:
        print("No cleartext credentials were captured.")
        return

    if ftp_credentials:
        print("\n--- FTP Credentials Captured ---")
        for cred in ftp_credentials:
            print(f"[{cred['time']}] {cred['protocol']}: {cred['src_ip']}:{cred['src_port']} -> {cred['dst_ip']} | {cred['type']}: {cred['value']}")

    if http_credentials:
        print("\n--- HTTP Credentials Captured ---")
        for cred in http_credentials:
            print(f"[{cred['time']}] {cred['protocol']}: {cred['src_ip']}:{cred['src_port']} -> {cred['dst_ip']} | {cred['type']}: {cred['value']}")
    print("\n" + "="*70)

def save_log_file():
    """Saves the captured credentials to a log file."""
    if not ftp_credentials and not http_credentials:
        return

    with open("credential_log.txt", "w") as log_file:
        log_file.write("Network Sniffer Log\n")
        log_file.write(f"Capture Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write("="*40 + "\n\n")

        if ftp_credentials:
            log_file.write("--- FTP Credentials ---\n")
            for cred in ftp_credentials:
                log_file.write(f"[{cred['time']}] {cred['protocol']}: {cred['src_ip']}:{cred['src_port']} -> {cred['dst_ip']} | {cred['type']}: {cred['value']}\n")
            log_file.write("\n")

        if http_credentials:
            log_file.write("--- HTTP Credentials ---\n")
            for cred in http_credentials:
                log_file.write(f"[{cred['time']}] {cred['protocol']}: {cred['src_ip']}:{cred['src_port']}-> {cred['dst_ip']} | {cred['type']}: {cred['value']}\n")

    print(f"[+] Log saved to: {os.path.abspath('credential_log.txt')}")

# --- Main Program ---

def main():
    print("Cleartext Credential Sniffer for Lab Environments 🧪")
    print("This tool is for educational purposes in a controlled lab only.\n")

    try:
        # Prompt user for network interface
        iface = input("Enter the network interface to sniff on (e.g., eth0, Wi-Fi, en0): ")

        # Choose between protocols
        print("\nChoose what to sniff:")
        print("1. FTP (port 21)")
        print("2. HTTP (port 80)")
        choice = input("Enter your choice (1, 2, or 3): ")

        # Set BPF filter based on choice
        if choice == '1':
            bpf_filter = "tcp port 21"
            prn_function = analyze_ftp_packet
        elif choice == '2':
            bpf_filter = "tcp port 80"
            prn_function = analyze_http_packet
        else:
            print("Invalid choice. Exiting.")
            return

        # Prompt for duration or packet count
        capture_type = input("Capture by (1) duration or (2) packet count? Enter 1 or 2: ")
        
        timeout_val, count_val = None, 0

        if capture_type == '1':
            timeout_val = int(input("Enter capture duration in seconds: "))
            print(f"\n[*] Sniffing on '{iface}' for {timeout_val} seconds... Press Ctrl+C to stop early.")
        elif capture_type == '2':
            count_val = int(input("Enter number of packets to capture: "))
            print(f"\n[*] Sniffing on '{iface}' for {count_val} packets... Press Ctrl+C to stop early.")
        else:
            print("Invalid choice. Exiting.")
            return

        # Start sniffing
        sniff(iface=iface, filter=bpf_filter, prn=prn_function, timeout=timeout_val, count=count_val)

    except PermissionError:
        print("\n[!] ERROR: This script requires root or administrator privileges to run.")
    except OSError as e:
        print(f"\n[!] ERROR: Interface '{iface}' not found or could not be opened. Please check the name and try again.")
    except KeyboardInterrupt:
        print("\n[+] Sniffing stopped by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
    finally:
        # Always print summary and save logs at the end
        print_summary()
        save_log_file()

if __name__ == "__main__":
    main()