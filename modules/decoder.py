#!/usr/bin/env python3
"""Decoder v3 — Base64, JWT, Hex, Unicode, URL, ROT13, Gzip"""
import base64, json, re, binascii, gzip, zlib
from urllib.parse import unquote

class Decoder:
    def _try_base64(self, v):
        for val in [v, v + "=", v + "=="]:
            try:
                dec = base64.b64decode(val).decode("utf-8", errors="ignore")
                if len(dec) > 5 and dec.isprintable():
                    return f"[B64] {dec[:250]}"
            except:
                pass
        try:
            val = v.replace("-","+").replace("_","/") + "=="
            dec = base64.urlsafe_b64decode(val).decode("utf-8", errors="ignore")
            if len(dec) > 5 and dec.isprintable():
                return f"[B64URL] {dec[:250]}"
        except:
            pass
        return None

    def _try_jwt(self, v):
        try:
            parts = v.split(".")
            if len(parts) != 3:
                return None
            def dp(p):
                p += "=" * (4 - len(p) % 4)
                return json.loads(base64.urlsafe_b64decode(p))
            hdr = dp(parts[0])
            pay = dp(parts[1])
            alg = hdr.get("alg","?")
            sub = pay.get("sub", pay.get("email", pay.get("user_id", pay.get("uid","?"))))
            exp = pay.get("exp","N/A")
            iss = pay.get("iss","")
            return f"[JWT] alg={alg} iss={iss} sub={sub} exp={exp} | payload={json.dumps(pay)[:200]}"
        except:
            return None

    def _try_hex(self, v):
        try:
            if re.match(r'^(0x)?[0-9a-fA-F]+$', v) and len(v) >= 16:
                raw = v[2:] if v.startswith("0x") else v
                if len(raw) % 2 == 0:
                    dec = binascii.unhexlify(raw).decode("utf-8", errors="ignore")
                    if dec.isprintable() and len(dec) > 4:
                        return f"[HEX] {dec[:250]}"
        except:
            pass
        return None

    def _try_gzip(self, v):
        try:
            raw = base64.b64decode(v + "==")
            dec = gzip.decompress(raw).decode("utf-8", errors="ignore")
            if len(dec) > 5:
                return f"[GZIP] {dec[:250]}"
        except:
            pass
        return None

    def _try_unicode(self, v):
        try:
            dec = v.encode().decode("unicode_escape")
            if dec != v and len(dec) > 3:
                return f"[UNICODE] {dec[:250]}"
        except:
            pass
        return None

    def _try_url(self, v):
        dec = unquote(v)
        if dec != v:
            return f"[URL] {dec[:250]}"
        return None

    def process(self, findings):
        print("[*] Decoding obfuscated/encoded values...")
        for f in findings:
            v = f.get("value","")
            t = f.get("type","")
            result = None

            if t == "JWT Token":
                result = self._try_jwt(v)
            elif t == "Basic Auth Encoded":
                result = self._try_base64(v)
            elif re.match(r'^(0x)?[0-9a-fA-F]{32,}$', v):
                result = self._try_hex(v)
            elif "%" in v:
                result = self._try_url(v)
            else:
                result = self._try_base64(v)
                if not result:
                    result = self._try_gzip(v)
                if not result:
                    result = self._try_unicode(v)

            if result:
                f["decoded"] = result
                print(f"  [+] Decoded {t}: {result[:80]}")
        return findings
