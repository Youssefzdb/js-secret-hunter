#!/usr/bin/env python3
"""
Environment Checker - Restricts tool to authorized/lab environments only
Blocks execution against public IPs outside defined scope
"""
import ipaddress
import socket
import re
from urllib.parse import urlparse

# Private/lab IP ranges (RFC1918 + loopback + link-local)
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Known CTF/lab platform domains
LAB_DOMAINS = [
    "htb", "hackthebox", "tryhackme", "thm", "vulnhub",
    "pwnable", "picoctf", "ctfd", "ctf", "lab", "local",
    "internal", "test", "dev", "staging", "pentest"
]

class EnvironmentChecker:
    def __init__(self, url, scope=None):
        self.url = url
        self.scope = scope
        self.parsed = urlparse(url)
        self.hostname = self.parsed.hostname or ""

    def _is_private_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in PRIVATE_RANGES)
        except:
            return False

    def _resolve_host(self):
        try:
            return socket.gethostbyname(self.hostname)
        except:
            return None

    def _is_lab_domain(self):
        hostname_lower = self.hostname.lower()
        return any(lab in hostname_lower for lab in LAB_DOMAINS)

    def _is_in_scope(self):
        if not self.scope:
            return None  # No scope defined
        # Check if hostname matches scope
        if self.scope in self.hostname or self.hostname in self.scope:
            return True
        # Check CIDR scope
        try:
            network = ipaddress.ip_network(self.scope, strict=False)
            ip = self._resolve_host()
            if ip and ipaddress.ip_address(ip) in network:
                return True
        except:
            pass
        return False

    def validate(self):
        print("[*] Environment check...")

        # 1. If scope explicitly defined and matches → allow
        if self.scope:
            in_scope = self._is_in_scope()
            if in_scope:
                print(f"[+] Target is within defined scope: {self.scope}")
                return True
            else:
                print(f"[!] BLOCKED: Target {self.hostname} is outside defined scope: {self.scope}")
                return False

        # 2. Check if lab/CTF domain
        if self._is_lab_domain():
            print(f"[+] Lab/CTF domain detected: {self.hostname}")
            return True

        # 3. Resolve and check private IP
        ip = self._resolve_host()
        if ip:
            if self._is_private_ip(ip):
                print(f"[+] Private/lab IP: {ip}")
                return True
            else:
                print(f"\n{'!'*55}")
                print(f"  WARNING: {self.hostname} resolves to PUBLIC IP: {ip}")
                print(f"  This tool is for AUTHORIZED targets only.")
                print(f"  Use --scope to define your authorized target scope.")
                print(f"{'!'*55}")
                confirm = input("\n  Type 'I HAVE AUTHORIZATION' to proceed: ").strip()
                if confirm == "I HAVE AUTHORIZATION":
                    print("[+] Authorization confirmed. Proceeding...")
                    return True
                return False

        # 4. Unknown host
        print(f"[!] Cannot resolve {self.hostname} — check target")
        return False
