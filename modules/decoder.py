#!/usr/bin/env python3
"""Decoder v2 - Base64, JWT, Hex, Unicode escapes, eval detection"""
import base64
import json
import re
import binascii

class Decoder:
    def _try_base64(self, value):
        for v in [value, value + "=", value + "=="]:
            try:
                decoded = base64.b64decode(v).decode("utf-8", errors="ignore")
                if len(decoded) > 6 and decoded.isprintable() and not decoded.startswith('\x00'):
                    return f"[B64] {decoded[:200]}"
            except:
                pass
        # URL-safe base64
        try:
            v = value.replace("-", "+").replace("_", "/")
            v += "=" * (4 - len(v) % 4)
            decoded = base64.b64decode(v).decode("utf-8", errors="ignore")
            if len(decoded) > 6 and decoded.isprintable():
                return f"[B64URL] {decoded[:200]}"
        except:
            pass
        return None

    def _try_jwt(self, value):
        try:
            parts = value.split(".")
            if len(parts) != 3:
                return None
            def decode_part(p):
                p += "=" * (4 - len(p) % 4)
                return json.loads(base64.urlsafe_b64decode(p))
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            alg = header.get("alg", "?")
            exp = payload.get("exp", "")
            sub = payload.get("sub", payload.get("email", payload.get("user", "")))
            return f"[JWT] alg={alg} sub={sub} exp={exp} | {json.dumps(payload)[:200]}"
        except:
            return None

    def _try_hex(self, value):
        try:
            if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0 and len(value) >= 16:
                decoded = binascii.unhexlify(value).decode("utf-8", errors="ignore")
                if decoded.isprintable() and len(decoded) > 4:
                    return f"[HEX] {decoded[:200]}"
        except:
            pass
        return None

    def _try_unicode(self, value):
        try:
            decoded = value.encode().decode("unicode_escape")
            if decoded != value and len(decoded) > 3:
                return f"[UNICODE] {decoded[:200]}"
        except:
            pass
        return None

    def _try_url_decode(self, value):
        try:
            from urllib.parse import unquote
            decoded = unquote(value)
            if decoded != value and len(decoded) > 3:
                return f"[URL] {decoded[:200]}"
        except:
            pass
        return None

    def process(self, findings):
        print("[*] Decoding obfuscated values...")
        for f in findings:
            value = f.get("value", "")
            t = f.get("type", "")
            decoded = None

            if t == "JWT Token":
                decoded = self._try_jwt(value)
            elif t in ["Basic Auth Header"]:
                decoded = self._try_base64(value)
            elif re.match(r'^[0-9a-fA-F]{32,}$', value):
                decoded = self._try_hex(value)
            elif "%" in value:
                decoded = self._try_url_decode(value)
            elif re.match(r'^[A-Za-z0-9+/=\-_]{40,}$', value):
                decoded = self._try_base64(value)
                if not decoded:
                    decoded = self._try_unicode(value)

            if decoded:
                f["decoded"] = decoded
                print(f"  [+] {t}: {decoded[:80]}")
        return findings
