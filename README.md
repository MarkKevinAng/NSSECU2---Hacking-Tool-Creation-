# NSSECU2 - Hacking-Tool-Creation-
Network Sniffer with Credential Detector

Develop a network sniffer tool that captures and analyzes network traffic on a lab environment. The tool will specifically identify and log any cleartext credentials transmitted via common protocols like HTTP and FTP.
This project will help students understand network-level data interception and the risks of unencrypted communication.
Functional Requirements:

The tool must capture live network packets on a specified network interface within a controlled lab environment.
It should filter and analyze network traffic for unencrypted protocols such as HTTP and FTP.
The tool must extract and log sensitive information such as usernames and passwords found in:
o    HTTP POST request parameters (e.g., login forms).
o    FTP commands for user authentication (e.g., USER and PASS commands).
All captured credentials and relevant packet details (source IP, destination IP, timestamp) must be saved to a local log file.
The tool should provide a summary of detected credentials at the end of the capture session.
It must allow the user to specify the capture duration or the number of packets to process before stopping.
The program must handle exceptions gracefully (e.g., permissions issues or unavailable interfaces) and notify the user.
