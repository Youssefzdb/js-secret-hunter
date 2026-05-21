#!/usr/bin/env python3
"""Decoder - Decode obfuscated values: Base64, JWT, URL encoding, hex"""
import base64
import json
import re
import binascii

class Decoder:
    def decode_base64(self, value):
        try:
            # Add padding if needed
            padded = value + "=" * (4 - len(value) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if len(decoded) > 3 and decoded.isprintable():
                return f"[BASE64] {decoded[:200]}"
        except:
            pass
        return None

    def decode_jwt(self, value):
        try:
            parts = value.split(".")
            if len(parts) == 3:
                # Decode header
                header_raw = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_raw))
                # Decode payload
                payload_raw = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_raw))
                return f"[JWT] alg={header.get('alg','?')} | {json.dumps(payload)[:200]}"
        except:
            pass
        return None

    def decode_hex(self, value):
        try:
            if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
                decoded = binascii.unhexlify(value).decode("utf-8", errors="ignore")
                if decoded.isprintable() and len(decoded) > 3:
                    return f"[HEX] {decoded[:200]}"
        except:
            pass
        return None

    def decode_url(self, value):
        try:
            from urllib.parse import unquote
            decoded = unquote(value)
            if decoded != value:
                return f"[URL] {decoded[:200]}"
        except:
            pass
        return None

    def process(self, findings):
        print("[*] Attempting to decode obfuscated values...")
        for f in findings:
            value = f.get("value", "")
            decoded = None

            if f["type"] == "JWT Token":
                decoded = self.decode_jwt(value)
            elif f["type"] == "Suspicious Base64":
                decoded = self.decode_base64(value)
            elif re.match(r'^[0-9a-fA-F]{20,}$', value):
                decoded = self.decode_hex(value)
            else:
                decoded = self.decode_url(value)
                if not decoded:
                    decoded = self.decode_base64(value)

            if decoded:
                f["decoded"] = decoded
                print(f"  [+] Decoded {f['type']}: {decoded[:60]}...")

        return findings
