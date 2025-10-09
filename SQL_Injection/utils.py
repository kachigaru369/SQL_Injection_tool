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
    """SQL escape for single quotes"""
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

def looks_encoded(s: str) -> bool:
    """Check if string looks URL-encoded"""
    encoded_chars = "%20", "%3C", "%3E", "%26", "%22", "%27"
    return any(encoded in s for encoded in encoded_chars)

def default_folder_input(prompt: str, default: str = None) -> str:
    """Prompt for a folder path with optional default"""
    if default is None:
        default = os.getcwd()
    folder = input(f"{prompt} [default: {default}]: ").strip()
    if not folder:
        return default
    if os.path.isdir(folder):
        return folder
    print(f"[-] '{folder}' is not a valid directory. Using default: {default}")
    return default

def _short_hash(s: str) -> str:
    """Generate a short hash of a string"""
    if not s:
        return "0"
    return hashlib.md5(s.encode('utf-8')).hexdigest()[:8]

def timed_send(ic, req, tries=3, quiet=False):
    """Send a request with timing and retry logic"""
    transient = {429, 502, 503, 504}
    backoff = 0.6
    t0 = time.perf_counter()
    r = ic.send(req, quiet=quiet, tries_override=tries)
    t1 = time.perf_counter()
    return r, t1 - t0

def validate_input(prompt: str, input_type: str = "str", valid_options=None, default=None):
    """Validate user input with retries"""
    while True:
        value = input(prompt).strip()
        if not value and default is not None:
            return default
        if valid_options and value not in valid_options:
            print(f"[-] Invalid input. Valid options: {valid_options}")
            continue
        try:
            if input_type == "int":
                return to_int_safe(value)
            elif input_type == "float":
                return float(value)
            elif input_type == "str":
                return value
            else:
                print(f"[-] Unsupported input type: {input_type}")
                continue
        except (ValueError, TypeError):
            print(f"[-] Invalid {input_type}. Try again.")
            continue

def save_results(results, filename: str):
    """Save results to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)
        print(f"[*] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save results: {e}")

def load_results(filename: str) -> dict:
    """Load results from JSON file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Failed to load results: {e}")
        return {}

def load_custom_payloads(filename: str = "custom_payloads.json"):
    """Load custom payload lists from JSON file"""
    file_path = os.path.join(os.path.dirname(__file__), filename)
    try:
        if not os.path.exists(file_path):
            print(f"[*] Creating default {filename}")
            default_data = {
                "lists": {
                    "sql_injection_basic": {
                        "payloads": ["' OR 1=1--", "' UNION SELECT NULL--"],
                        "metadata": {"dbms": ["generic"], "type": "basic"}
                    },
                    "union_tests": {
                        "payloads": ["' UNION SELECT 1,2,3--", "' UNION SELECT database()--"],
                        "metadata": {"dbms": ["MySQL"], "type": "union"}
                    },
                    "time_based": {
                        "payloads": ["' AND SLEEP(5)--", "' AND pg_sleep(5)--"],
                        "metadata": {"dbms": ["MySQL", "PostgreSQL"], "type": "time-based"}
                    }
                }
            }
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, ensure_ascii=False, indent=2)
            return default_data.get("lists", {})
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            lists = data.get("lists", {})
            # Ensure compatibility with new format
            for list_name, list_data in lists.items():
                if isinstance(list_data, list):
                    # Old format - convert to new format
                    lists[list_name] = {
                        "payloads": list_data,
                        "metadata": {"dbms": ["generic"], "type": "generic"}
                    }
            return lists
    except Exception as e:
        print(f"[-] Failed to load {filename}: {e}")
        return {}

def save_custom_payloads(payload_lists: dict, filename: str = "custom_payloads.json"):
    """Save custom payload lists to JSON file"""
    file_path = os.path.join(os.path.dirname(__file__), filename)
    data = {"lists": payload_lists}
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[*] Custom payload lists saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save {filename}: {e}")