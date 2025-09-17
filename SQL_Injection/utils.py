import re
import json
import time
from xml.sax.saxutils import escape as _xml_escape
import hashlib
import os

def to_int_safe(s: str, min_val=None, max_val=None):
    fa = "۰۱۲۳۴۵۶۷۸۹"
    en = "0123456789"
    s = s.strip().translate(str.maketrans(fa, en))
    try:
        n = int(s)
        if min_val is not None and n < min_val:
            raise ValueError("out of range")
        if max_val is not None and n > max_val:
            raise ValueError("out of range")
        return n
    except ValueError:
        return None

def parse_multi_indices(s: str, max_len: int):
    s = s.strip().lower()
    if s in ("all", "a", "*"):
        return list(range(1, max_len + 1))
    fa = "۰۱۲۳۴۵۶۷۸۹"
    en = "0123456789"
    s = s.translate(str.maketrans(fa, en))
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            l, r = part.split("-", 1)
            l, r = int(l), int(r)
            for i in range(min(l, r), max(l, r) + 1):
                if 1 <= i <= max_len:
                    out.add(i)
        else:
            i = int(part)
            if 1 <= i <= max_len:
                out.add(i)
    return sorted(out)

def sql_escape(s: str) -> str:
    return s.replace("'", "''")

def escape_html(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))

def json_escape_str(s: str) -> str:
    return json.dumps(s)[1:-1]

def xml_escape_str(s: str) -> str:
    return _xml_escape(s, entities={"'": "&apos;", '"': "&quot;"})

def js_string_escape(s: str) -> str:
    return (s.replace("\\", "\\\\")
             .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
             .replace("\"", "\\\"").replace("'", "\\'")
             .replace("<", "\\x3c").replace(">", "\\x3e").replace("&", "\\x26"))

def apply_context_escape(s: str, ctx: str) -> str:
    ctx = (ctx or "raw").lower()
    if ctx == "json":
        return json_escape_str(s)
    if ctx == "xml":
        return xml_escape_str(s)
    if ctx == "html":
        return escape_html(s)
    if ctx in ("js", "javascript"):
        return js_string_escape(s)
    return s

def default_folder_input(prompt_text: str):
    base = os.path.dirname(os.path.abspath(__file__))
    raw = input(prompt_text).strip()
    if not raw:
        return base
    if os.path.isabs(raw):
        return raw
    return os.path.join(base, raw)

def _short_hash(s: str):
    if not s:
        return "-"
    data = s[:65536].encode("utf-8", errors="ignore")
    return hashlib.sha1(data).hexdigest()[:10]

def looks_encoded(s: str) -> bool:
    ENCODED_RX = re.compile(r"%[0-9A-Fa-f]{2}")
    return bool(ENCODED_RX.search(s or ""))

def timed_send(ic, req, quiet: bool = False, tries_override: int = None):
    t0 = time.perf_counter()
    r = ic.send(req, quiet=quiet, tries_override=tries_override)
    dt = time.perf_counter() - t0
    return r, dt

def validate_input(prompt: str, input_type: str = "str", default=None, valid_options: list = None):
    """اعتبارسنجی ورودی کاربر"""
    while True:
        value = input(prompt).strip()
        if not value and default is not None:
            return default
        try:
            if input_type == "int":
                value = int(value)
                if valid_options and value not in valid_options:
                    print(f"[-] Must be one of {valid_options}")
                    continue
            elif input_type == "float":
                value = float(value)
            elif input_type == "str" and valid_options:
                if value not in valid_options:
                    print(f"[-] Must be one of {valid_options}")
                    continue
            return value
        except ValueError:
            print(f"[-] Invalid {input_type}. Try again.")

def save_results(results: dict, filename: str):
    """ذخیره نتایج در فایل JSON"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[*] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save results: {e}")

def load_results(filename: str) -> dict:
    """بارگذاری نتایج از فایل JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Failed to load results: {e}")
        return None

def load_custom_payloads(filename: str = "custom_payloads.json"):
    """بارگذاری لیست‌های دلخواه payloadها از فایل JSON"""
    file_path = os.path.join(os.path.dirname(__file__), filename)
    try:
        if not os.path.exists(file_path):
            print(f"[*] Creating default {filename}")
            default_data = {
                "lists": {
                    "sql_injection_basic": ["' OR 1=1--", "' UNION SELECT NULL--"],
                    "union_tests": ["' UNION SELECT 1,2,3--", "' UNION SELECT database()--"],
                    "time_based": ["' AND SLEEP(5)--", "' AND pg_sleep(5)--"]
                }
            }
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, ensure_ascii=False, indent=2)
            return default_data["lists"]
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("lists", {})
    except Exception as e:
        print(f"[-] Failed to load {filename}: {e}")
        return {}

def save_custom_payloads(payload_lists: dict, filename: str = "custom_payloads.json"):
    """ذخیره لیست‌های دلخواه payloadها در فایل JSON"""
    file_path = os.path.join(os.path.dirname(__file__), filename)
    data = {"lists": payload_lists}
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[*] Custom payload lists saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save {filename}: {e}")