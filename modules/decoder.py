#!/usr/bin/env python3
"""Decoder v3 - JWT, Base64, Hex, ROT13, Unicode, JS obfuscation deobfuscation"""
import base64, json, re, binascii, codecs

class Decoder:

    def decode_jwt(self, value):
        try:
            parts = value.split(".")
            if len(parts) == 3:
                header_raw = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_raw))
                payload_raw = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_raw))
                return {
                    "format": "JWT",
                    "algorithm": header.get("alg", "?"),
                    "type": header.get("typ", "JWT"),
                    "payload": payload,
                    "text": f"alg={header.get('alg','?')} | {json.dumps(payload, ensure_ascii=False)[:300]}"
                }
        except:
            pass
        return None

    def decode_base64(self, value):
        for variant in [value, value.replace("-", "+").replace("_", "/")]:
            try:
                padded = variant + "=" * (4 - len(variant) % 4)
                decoded = base64.b64decode(padded)
                # Try UTF-8
                text = decoded.decode("utf-8")
                if len(text) > 4 and any(c.isalpha() for c in text[:20]):
                    return {"format": "BASE64", "text": text[:300]}
            except:
                pass
        return None

    def decode_hex(self, value):
        clean = re.sub(r'[^0-9a-fA-F]', '', value)
        if len(clean) >= 16 and len(clean) % 2 == 0:
            try:
                decoded = binascii.unhexlify(clean).decode("utf-8", errors="ignore")
                if len(decoded) > 3 and any(c.isalpha() for c in decoded):
                    return {"format": "HEX", "text": decoded[:300]}
            except:
                pass
        return None

    def decode_unicode_escape(self, value):
        try:
            decoded = value.encode().decode("unicode_escape")
            if decoded != value and any(c.isalpha() for c in decoded):
                return {"format": "UNICODE", "text": decoded[:300]}
        except:
            pass
        return None

    def decode_url_encoding(self, value):
        try:
            from urllib.parse import unquote
            decoded = unquote(value)
            if decoded != value:
                return {"format": "URL_ENCODED", "text": decoded[:300]}
        except:
            pass
        return None

    def decode_rot13(self, value):
        try:
            decoded = codecs.decode(value, "rot13")
            # Only return if it looks like meaningful text
            english_words = ["the", "and", "for", "api", "key", "secret", "token", "pass", "auth"]
            if any(w in decoded.lower() for w in english_words):
                return {"format": "ROT13", "text": decoded[:300]}
        except:
            pass
        return None

    def try_deobfuscate_js(self, value):
        """Try basic JS string deobfuscation patterns"""
        # \xNN hex escape
        try:
            decoded = re.sub(r'\\x([0-9a-fA-F]{2})',
                           lambda m: chr(int(m.group(1), 16)), value)
            if decoded != value:
                return {"format": "JS_HEX_ESCAPE", "text": decoded[:300]}
        except:
            pass

        # \uNNNN unicode escape
        try:
            decoded = re.sub(r'\\u([0-9a-fA-F]{4})',
                           lambda m: chr(int(m.group(1), 16)), value)
            if decoded != value:
                return {"format": "JS_UNICODE_ESCAPE", "text": decoded[:300]}
        except:
            pass

        return None

    def process(self, findings):
        print("[*] Decoding & deobfuscating values...")
        decoded_count = 0

        for f in findings:
            value = f.get("value", "")
            result = None
            t = f.get("type", "")

            # JWT first
            if t == "JWT Token" or (value.startswith("eyJ") and value.count(".") == 2):
                result = self.decode_jwt(value)

            # Base64 for long strings
            if not result and len(value) > 20:
                result = self.decode_base64(value)

            # Hex
            if not result:
                result = self.decode_hex(value)

            # JS escape sequences
            if not result:
                result = self.try_deobfuscate_js(value)

            # URL encoding
            if not result:
                result = self.decode_url_encoding(value)

            if result:
                f["decoded"] = result
                decoded_count += 1
                preview = result["text"][:80].replace("\n", " ")
                print(f"  [+] {result['format']}: {preview}")

        print(f"[+] Decoded {decoded_count}/{len(findings)} values")
        return findings
