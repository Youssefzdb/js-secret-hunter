#!/usr/bin/env python3
"""
Secret Decoder — tries Base64, Hex, URL, Unicode, ROT13, XOR, JWT, atob()
"""
import base64, binascii, urllib.parse, codecs, json, re


class SecretDecoder:
    def __init__(self, logger):
        self.log = logger

    def _b64(self, v):
        for s in [v, v.replace('-','+').replace('_','/')]:
            padded = s + '=' * (-len(s) % 4)
            try:
                dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
                ok  = sum(1 for c in dec if c.isprintable())
                if ok / max(len(dec),1) > 0.70 and len(dec) > 4:
                    return f"[BASE64] {dec[:250]}"
            except: pass
        return None

    def _hex(self, v):
        clean = re.sub(r'[^0-9a-fA-F]','', v)
        if len(clean) >= 8 and len(clean) % 2 == 0:
            try:
                dec = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                ok  = sum(1 for c in dec if c.isprintable())
                if ok / max(len(dec),1) > 0.70 and len(dec) > 3:
                    return f"[HEX] {dec[:250]}"
            except: pass
        # \xNN escapes
        esc = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1),16)), v)
        if esc != v:
            return f"[HEX-ESC] {esc[:250]}"
        return None

    def _url(self, v):
        if '%' in v:
            dec = urllib.parse.unquote(v)
            if dec != v:
                return f"[URL] {dec[:250]}"
        return None

    def _unicode(self, v):
        if '\\u' in v:
            try:
                dec = v.encode('utf-8').decode('unicode_escape')
                if dec != v:
                    return f"[UNICODE] {dec[:250]}"
            except: pass
        return None

    def _rot13(self, v):
        if not re.search(r'[a-zA-Z]{4,}', v):
            return None
        dec = codecs.decode(v, 'rot_13')
        if dec != v and re.search(r'[a-z]{3,}', dec):
            return f"[ROT13] {dec[:250]}"
        return None

    def _jwt(self, v):
        parts = v.split('.')
        if len(parts) == 3:
            try:
                h = json.loads(base64.b64decode(parts[0]+'==').decode('utf-8','ignore'))
                p = json.loads(base64.b64decode(parts[1]+'==').decode('utf-8','ignore'))
                return f"[JWT] alg={h.get('alg','?')} | {json.dumps(p)[:300]}"
            except: pass
        return None

    def _atob(self, v):
        m = re.search(r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)', v)
        if m:
            try:
                dec = base64.b64decode(m.group(1)+'==').decode('utf-8','ignore')
                return f"[atob()] {dec[:250]}"
            except: pass
        return None

    def _xor(self, v):
        clean = re.sub(r'[^0-9a-fA-F]','', v)
        if len(clean) < 16 or len(clean) % 2 != 0:
            return None
        try:
            data = bytes.fromhex(clean)
        except: return None
        for key in range(1,256):
            candidate = bytes(b ^ key for b in data)
            if sum(32 <= b <= 126 for b in candidate) / len(data) > 0.88:
                return f"[XOR key=0x{key:02X}] {candidate.decode('ascii','replace')[:200]}"
        return None

    def decode(self, value: str):
        if not value or len(value) < 6:
            return None
        for fn in [self._jwt, self._atob, self._b64, self._hex,
                   self._url, self._unicode, self._rot13, self._xor]:
            try:
                r = fn(value)
                if r:
                    return r
            except: pass
        return None
