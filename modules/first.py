import socket
import subprocess
import sys
import os

def scan_ports(target_host):
    startport = int(input("Enter the starting port: "))
    endport = int(input("Enter the ending port: "))
    for port in range(startport, endport + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()

def dns_lookup(hostname):
    ip = socket.gethostbyname(hostname)
    print(f"Hostname: {hostname}\nIP: {ip}")



