#!/usr/bin/env python3
"""Decoder v2 - Base64, JWT, Hex, ROT13, URL, Unicode, JS eval patterns"""
import base64, json, re, binascii
from urllib.parse import unquote

class Decoder:
    def _try_base64(self, value):
        try:
            padded = value + "=" * (4 - len(value) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            printable = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
            if printable > 0.85 and len(decoded) > 4:
                return f"[BASE64] {decoded[:300]}"
        except:
            pass
        return None

    def _try_jwt(self, value):
        try:
            parts = value.split(".")
            if len(parts) == 3:
                def _decode_part(p):
                    p += "=" * (4 - len(p) % 4)
                    return json.loads(base64.urlsafe_b64decode(p))
                header  = _decode_part(parts[0])
                payload = _decode_part(parts[1])
                alg = header.get("alg", "?")
                exp = payload.get("exp", "")
                sub = payload.get("sub", payload.get("email", payload.get("user", "")))
                return f"[JWT] alg={alg} sub={sub} exp={exp} | {json.dumps(payload)[:200]}"
        except:
            pass
        return None

    def _try_hex(self, value):
        clean = re.sub(r'[^0-9a-fA-F]', '', value)
        if len(clean) >= 8 and len(clean) % 2 == 0:
            try:
                decoded = binascii.unhexlify(clean).decode("utf-8", errors="ignore")
                printable = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
                if printable > 0.8 and len(decoded) > 3:
                    return f"[HEX] {decoded[:200]}"
            except:
                pass
        return None

    def _try_url(self, value):
        try:
            decoded = unquote(value)
            if decoded != value and len(decoded) > 4:
                return f"[URL] {decoded[:200]}"
        except:
            pass
        return None

    def _try_unicode_escape(self, value):
        try:
            decoded = value.encode().decode("unicode_escape")
            if decoded != value and len(decoded) > 3:
                return f"[UNICODE] {decoded[:200]}"
        except:
            pass
        return None

    def _try_rot13(self, value):
        import codecs
        try:
            decoded = codecs.decode(value, "rot_13")
            # ROT13 is only useful if result looks like a real string
            if re.search(r'[a-zA-Z]{3,}', decoded):
                return f"[ROT13] {decoded[:200]}"
        except:
            pass
        return None

    def process(self, findings):
        print("[*] Decoding obfuscated values...")
        for f in findings:
            value = f.get("value", "")
            decoded = None

            if f["type"] == "JWT Token" or value.startswith("eyJ"):
                decoded = self._try_jwt(value)
            elif f["type"] in ["Suspicious Base64", "Long Base64 String"] or len(value) % 4 == 0:
                decoded = self._try_base64(value)
            elif re.match(r'^[0-9a-fA-F]+$', value):
                decoded = self._try_hex(value)
            else:
                decoded = self._try_url(value) or self._try_unicode_escape(value) or self._try_base64(value)

            if decoded:
                f["decoded"] = decoded
                print(f"  [+] Decoded {f['type']}: {decoded[:70]}...")

        return findings
