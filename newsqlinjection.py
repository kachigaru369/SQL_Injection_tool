import requests
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse, urljoin
from urllib.parse import quote
import sys, os, re, time, itertools
import importlib.util
from time import perf_counter
import json
from xml.sax.saxutils import escape as _xml_escape
import random
import base64
# Optional deps
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False
# Playwright (optional)
PW_AVAILABLE = True
try:
    from playwright.sync_api import sync_playwright
except Exception:
    PW_AVAILABLE = False
# ------------------- utils -------------------
def to_int_safe(s: str, min_val=None, max_val=None):
    fa = "۰۱۲۳۴۵۶۷۸۹"
    en = "0123456789"
    s = s.strip().translate(str.maketrans(fa, en))
    n = int(s)
    if min_val is not None and n < min_val: raise ValueError("out of range")
    if max_val is not None and n > max_val: raise ValueError("out of range")
    return n
def parse_multi_indices(s: str, max_len: int):
    """
    '1,3-5,7' -> [1,3,4,5,7] (1-based indices)
    supports 'all', 'a', '*'
    """
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
                if 1 <= i <= max_len: out.add(i)
        else:
            i = int(part)
            if 1 <= i <= max_len: out.add(i)
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
    # فقط بخش داخل کوتیشن JSON را می‌سازد (بدون کوتیشن‌های اطراف)
    return json.dumps(s)[1:-1]
def xml_escape_str(s: str) -> str:
    return _xml_escape(s, entities={"'": "&apos;", '"': "&quot;"})
def js_string_escape(s: str) -> str:
    # Escape ساده و کاربردی برای قرارگیری داخل رشته JS
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
    return s # raw
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
ENCODED_RX = re.compile(r"%[0-9A-Fa-f]{2}")
def looks_encoded(s: str) -> bool:
    """A very simple heuristic: has %HH patterns."""
    return bool(ENCODED_RX.search(s or ""))
def timed_send(ic, req, quiet: bool = False, tries_override: int = None):
    t0 = perf_counter()
    r = ic.send(req, quiet=quiet, tries_override=tries_override)
    dt = perf_counter() - t0
    return r, dt
# ---------- placeholder helpers ----------
PLACEHOLDER_RX = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
def find_placeholders_in_string(s: str):
    return list(dict.fromkeys(PLACEHOLDER_RX.findall(str(s) or "")))
def find_placeholders_in_dict(d: dict):
    found = []
    for v in d.values():
        found += find_placeholders_in_string(v)
    out = []
    for x in found:
        if x not in out:
            out.append(x)
    return out
def parse_list_or_single(prompt_txt: str):
    """
    Input:
      - "abc" -> ["abc"]
      - "[a,b,c]" -> ["a","b","c"]
      - "" -> []
    """
    raw = input(prompt_txt).strip()
    if not raw:
        return []
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1]
        items = [i.strip() for i in inner.split(",") if i.strip() != ""]
        return items
    return [raw]
def expand_one_payload_string(s: str, var_map: dict):
    vars_in = find_placeholders_in_string(s)
    if not vars_in:
        return [("", s)]
    lists = []
    for v in vars_in:
        vals = var_map.get(v, [])
        if not vals:
            print(f"[!] No value provided for placeholder {{{v}}}, skipping this payload.")
            return []
        lists.append([(v, val) for val in vals])
    combos = list(itertools.product(*lists))
    out = []
    for combo in combos:
        filled = s
        parts = []
        for (vn, vv) in combo:
            filled = filled.replace("{"+vn+"}", str(vv))
            parts.append(f"{vn}={vv}")
        label_suffix = "|".join(parts)
        out.append((label_suffix, filled))
    return out
def expand_payload_dict(payload_dict: dict):
    vars_all = find_placeholders_in_dict(payload_dict)
    var_map = {}
    for v in vars_all:
        vals = parse_list_or_single(f"Value(s) for placeholder {{{v}}} (single or [a,b,c]): ")
        if not vals:
            print(f"[!] No values entered for {{{v}}}. This var will be skipped in expansions.")
        var_map[v] = vals
    expanded = {}
    for label, s in payload_dict.items():
        variants = expand_one_payload_string(s, var_map)
        if not variants:
            continue
        for label_suffix, filled in variants:
            new_label = label if not label_suffix else f"{label}|{label_suffix}"
            expanded[new_label] = filled
    return expanded
def expand_single_payload_string(s: str):
    vars_in = find_placeholders_in_string(s)
    if not vars_in:
        return {"p0": s}
    var_map = {}
    for v in vars_in:
        vals = parse_list_or_single(f"Value(s) for placeholder {{{v}}} (single or [a,b,c]): ")
        if not vals:
            print(f"[!] No values entered for {{{v}}}. Skipping.")
            return {}
        var_map[v] = vals
    out = {}
    for label_suffix, filled in expand_one_payload_string(s, var_map):
        new_label = "p0" if not label_suffix else f"p0|{label_suffix}"
        out[new_label] = filled
    return out
# ------------------- core -------------------
class InputCollector:
    def __init__(self, url, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.injection_mode = "append" # or "replace"
        self.encode_cookies = "auto" # "auto" | "encode" | "raw"
        self.encode_headers = "auto" # "auto" | "encode" | "raw"
        self.set_url(url)
        self.context_mode = "raw" # raw | json | xml | html | js
    def preview_transform(self, key: str, payload_str: str):
        raw = str(payload_str)
        ctx = apply_context_escape(raw, getattr(self, "context_mode", "raw"))
        pt = self.prepared_data["type"] if self.prepared_data else None
        final = ctx
        try:
            if pt == "url":
                parsed = self.prepared_data["parsed"]
                params = {k: v[:] for k, v in self.prepared_data["params"].items()}
                orig = self.original_values.get(key, "")
                val = (orig + ctx) if (self.injection_mode == "append") else ctx
                params[key] = [val]
                new_query = urlencode(params, doseq=True)
                final_url = urlunparse(parsed._replace(query=new_query))
                final = final_url
            elif pt == "post":
                fields = self.prepared_data["fields"].copy()
                orig = self.original_values.get(key, "")
                val = (orig + ctx) if (self.injection_mode == "append") else ctx
                fields[key] = val
                method = self.prepared_data.get("method", "POST").upper()
                action_url = self.prepared_data.get("action_url", self.url)
                if method == "GET":
                    parsed = urlparse(action_url)
                    base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
                    base_params.update(fields)
                    new_query = urlencode(base_params, doseq=True)
                    final = urlunparse(parsed._replace(query=new_query))
                else:
                    final = f"{action_url} | data=" + urlencode(fields)
            elif pt == "cookie":
                cookies = self.prepared_data["cookies"].copy()
                orig = str(self.original_values.get(key, ""))
                use_encode = (
                    self.encode_cookies == "encode" or
                    (self.encode_cookies == "auto" and looks_encoded(orig))
                )
                payload_piece = quote(ctx, safe="") if use_encode else ctx
                val = (orig + payload_piece) if (self.injection_mode == "append") else payload_piece
                cookies[key] = val
                final = f"{self.url} | Cookie {key}={cookies[key]}"
            elif pt == "header":
                headers = self.prepared_data["headers"].copy()
                orig = str(self.original_values.get(key, ""))
                use_encode = (
                    self.encode_headers == "encode" or
                    (self.encode_headers == "auto" and looks_encoded(orig))
                )
                payload_piece = quote(ctx, safe="") if use_encode else ctx
                val = (orig + payload_piece) if (self.injection_mode == "append") else payload_piece
                headers[key] = val
                final = f"{self.url} | Header {key}: {headers[key]}"
        except Exception as e:
            final = f"[preview-error] {e}"
        return {"RAW": raw, "CTX": ctx, "FINAL": final}
    def set_context_mode(self, mode: str):
        mode = (mode or "raw").lower()
        if mode not in {"raw", "json", "xml", "html", "js"}:
            print("[-] Invalid context mode. Using raw.")
            mode = "raw"
        self.context_mode = mode
        print(f"[*] context_mode -> {self.context_mode}")
    def set_url(self, url):
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        self.url = url
        self.response = None
        try:
            self.response = self.session.get(self.url, timeout=self.timeout)
        except Exception as e:
            print(f"[-] Initial GET failed: {e}")
        self.target_type = None
        self.selected_keys = []
        self.original_values = {}
        self.prepared_data = None
    # -------- menus --------
    def choose_target_type(self):
        while True:
            print("\nSelect target to test:")
            print("1. URL Parameter")
            print("2. POST Field (auto-discover forms)")
            print("3. Cookie")
            print("4. Header")
            print("9. Back")
            print("0. Cancel")
            try:
                choice = to_int_safe(input("Your choice: "), 0, 9)
            except Exception:
                print("[-] Invalid number. Try again.")
                continue
            if choice == 0: return None
            if choice == 9: return "back"
            self.target_type = choice
            return choice
    def collect_inputs(self):
        if self.target_type == 1:
            return self._collect_url_params()
        elif self.target_type == 2:
            return self._collect_post_fields()
        elif self.target_type == 3:
            return self._collect_cookies()
        elif self.target_type == 4:
            return self._collect_headers()
        else:
            print("[-] No target type selected.")
            return False
    # -------- collectors --------
    def _collect_url_params(self):
        parsed = urlparse(self.url)
        params = {k: v[:] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        keys = list(params.keys())
        if not keys:
            print("No URL parameters found.")
            ans = input("Add a new query parameter? (y/n): ").strip().lower()
            if ans == "y":
                k = input("Param name: ").strip()
                v = input("Param value: ").strip()
                params = {k: [v]}
                keys = [k]
            else:
                return False
        print("\nURL Parameters:")
        for i, k in enumerate(keys, start=1):
            print(f"{i}. {k} = {params[k]}")
        print("Select one/many (e.g., 1,3-4 or 'all') | 9: Back | 0: Cancel")
        sel = input("Indices: ").strip()
        if sel in ("9", "۹"): return "back"
        if sel in ("0", "۰"): return False
        try:
            indices = parse_multi_indices(sel, len(keys))
        except Exception:
            print("[-] Invalid selection.")
            return False
        if not indices:
            print("[-] Nothing selected.")
            return False
        self.selected_keys = [keys[i-1] for i in indices]
        self.original_values = {k: (params[k][0] if params[k] else "") for k in self.selected_keys}
        self.prepared_data = {"type": "url", "params": params, "parsed": parsed}
        return True
    def _discover_forms(self):
        if not HAS_BS4:
            print("[-] BeautifulSoup not installed. Run: pip install beautifulsoup4")
            return []
        if not self.response:
            try:
                self.response = self.session.get(self.url, timeout=self.timeout)
            except Exception as e:
                print(f"[-] GET failed for form discovery: {e}")
                return []
        soup = BeautifulSoup(self.response.text, "html.parser")
        forms = soup.find_all("form")
        results = []
        for f in forms:
            method = (f.get("method") or "GET").upper()
            action = f.get("action") or self.url
            action_abs = urljoin(self.url, action)
            fields = {}
            for inp in f.find_all("input"):
                name = inp.get("name")
                if not name: continue
                value = inp.get("value", "")
                fields[name] = value
            for ta in f.find_all("textarea"):
                name = ta.get("name")
                if not name: continue
                value = ta.text or ""
                fields[name] = value
            for sel in f.find_all("select"):
                name = sel.get("name")
                if not name: continue
                val = ""
                options = sel.find_all("option")
                if options:
                    sel_opt = next((o for o in options if o.get("selected")), options[0])
                    val = sel_opt.get("value", sel_opt.text)
                fields[name] = val
            results.append({"method": method, "action": action_abs, "inputs": fields, "form": f})
        return results
    def _collect_post_fields(self):
        forms = self._discover_forms()
        if not forms:
            print("[-] No forms found.")
            return False
        print(f"[+] Found {len(forms)} form(s):")
        for i, f in enumerate(forms, start=1):
            print(f"{i}. Method={f['method']} | Action={f['action']} | Fields={list(f['inputs'].keys())}")
        print("Pick a form (number) | 9: Back | 0: Cancel")
        sel = input("> ").strip()
        if sel in ("9", "۹"): return "back"
        if sel in ("0", "۰"): return False
        try:
            idx = to_int_safe(sel, 1, len(forms)) - 1
        except Exception:
            print("[-] Invalid selection.")
            return False
        selected = forms[idx]
        fields = selected["inputs"]
        if not fields:
            print("[-] This form has no named fields.")
            return False
        keys = list(fields.keys())
        print("\n[+] Fields:")
        for i, k in enumerate(keys, start=1):
            print(f"{i}. {k} = {fields[k]}")
        print("Select one/many (e.g., 1,2-3 or 'all') | 9: Back | 0: Cancel")
        sel2 = input("Indices: ").strip()
        if sel2 in ("9", "۹"): return "back"
        if sel2 in ("0", "۰"): return False
        try:
            indices = parse_multi_indices(sel2, len(keys))
        except Exception:
            print("[-] Invalid selection.")
            return False
        if not indices:
            print("[-] Nothing selected.")
            return False
        self.selected_keys = [keys[i-1] for i in indices]
        self.original_values = {k: fields[k] for k in self.selected_keys}
        self.prepared_data = {
            "type": "post",
            "fields": fields.copy(),
            "method": selected["method"],
            "action_url": selected["action"]
        }
        return True
    def _collect_cookies(self):
        cookies_dict = {}
        try:
            if self.response is None:
                self.response = self.session.get(self.url, timeout=self.timeout)
            cookies_dict = self.response.cookies.get_dict()
        except Exception as e:
            print(f"[-] Could not fetch cookies: {e}")
        if not cookies_dict:
            print("[-] No cookies found in session.")
            return False
        keys = list(cookies_dict.keys())
        print("\nCookies:")
        for i, k in enumerate(keys, start=1):
            print(f"{i}. {k} = {cookies_dict[k]}")
        print("Select one/many (e.g., 1,3-4 or 'all') | 9: Back | 0: Cancel")
        sel = input("Indices: ").strip()
        if sel in ("9", "۹"): return "back"
        if sel in ("0", "۰"): return False
        try:
            indices = parse_multi_indices(sel, len(keys))
        except Exception:
            print("[-] Invalid selection.")
            return False
        if not indices:
            print("[-] Nothing selected.")
            return False
        self.selected_keys = [keys[i-1] for i in indices]
        self.original_values = {k: cookies_dict[k] for k in self.selected_keys}
        self.prepared_data = {"type": "cookie", "cookies": cookies_dict.copy()}
        return True
    def _collect_headers(self):
        default_headers = {
            "User-Agent": (self.response.request.headers.get("User-Agent") if self.response else "Mozilla/5.0") or "Mozilla/5.0",
            "Referer": self.url
        }
        keys = list(default_headers.keys()) + ["(custom)"]
        while True:
            print("\nHeaders:")
            for i, k in enumerate(keys, start=1):
                if k == "(custom)":
                    print(f"{i}. {k}")
                else:
                    print(f"{i}. {k} = {default_headers[k]}")
            print("Select one/many (e.g., 1,2 or 'all') | 8: Add custom | 9: Back | 0: Cancel")
            sel = input("Indices: ").strip()
            if sel in ("9", "۹"): return "back"
            if sel in ("0", "۰"): return False
            if sel in ("8", "۸"):
                hk = input("Header name: ").strip()
                hv = input("Header value: ").strip()
                if hk:
                    default_headers[hk] = hv
                    keys = list(default_headers.keys()) + ["(custom)"]
                continue
            try:
                indices = parse_multi_indices(sel, len(keys))
            except Exception:
                print("[-] Invalid selection.")
                continue
            indices = [i for i in indices if i <= len(keys)-1]
            if not indices:
                print("[-] Nothing selected.")
                continue
            self.selected_keys = [list(default_headers.keys())[i-1] for i in indices]
            self.original_values = {k: default_headers[k] for k in self.selected_keys}
            self.prepared_data = {"type": "header", "headers": default_headers.copy()}
            return True
    # -------- builder --------
    def _build_one(self, key, payload_str):
        pt = self.prepared_data["type"]
        p = str(payload_str)
        # 1) Context escape (RAW -> JSON/XML/HTML/JS)
        p_ctx = apply_context_escape(p, getattr(self, "context_mode", "raw"))
        try:
            if pt == "url":
                params = {k: v[:] for k, v in self.prepared_data["params"].items()}
                orig = self.original_values.get(key, "")
                val = (orig + p_ctx) if (self.injection_mode == "append") else p_ctx
                params[key] = [val]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(self.prepared_data["parsed"]._replace(query=new_query))
                return {"url": new_url, "method": "GET"}
            if pt == "post":
                fields = self.prepared_data["fields"].copy()
                orig = self.original_values.get(key, "")
                val = (orig + p_ctx) if (self.injection_mode == "append") else p_ctx
                fields[key] = val
                method = self.prepared_data.get("method", "POST").upper()
                action_url = self.prepared_data.get("action_url", self.url)
                if method == "GET":
                    parsed = urlparse(action_url)
                    base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
                    base_params.update(fields)
                    new_query = urlencode(base_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    return {"url": new_url, "method": "GET"}
                return {"url": action_url, "method": "POST", "data": fields}
            if pt == "cookie":
                cookies = self.prepared_data["cookies"].copy()
                orig = str(self.original_values.get(key, ""))
                use_encode = (
                    self.encode_cookies == "encode" or
                    (self.encode_cookies == "auto" and looks_encoded(orig))
                )
                payload_piece = quote(p_ctx, safe="") if use_encode else p_ctx
                val = (orig + payload_piece) if (getattr(self, "injection_mode", "append") == "append") else payload_piece
                cookies[key] = val
                return {"url": self.url, "method": "GET", "cookies": cookies}
            if pt == "header":
                headers = self.prepared_data["headers"].copy()
                orig = str(self.original_values.get(key, ""))
                use_encode = (
                    self.encode_headers == "encode" or
                    (self.encode_headers == "auto" and looks_encoded(orig))
                )
                payload_piece = quote(p_ctx, safe="") if use_encode else p_ctx
                val = (orig + payload_piece) if (getattr(self, "injection_mode", "append") == "append") else payload_piece
                headers[key] = val
                return {"url": self.url, "method": "GET", "headers": headers}
        except Exception as e:
            print(f"[-] build error for {pt}:{key}: {e}")
            return None
    def prepare_injection(self, payload):
        if not self.prepared_data or not self.selected_keys:
            print("[-] Nothing prepared. Run collect_inputs() first.")
            return None
        pt = self.prepared_data["type"]
        if isinstance(payload, dict):
            out = {}
            for label, p in payload.items():
                sub = {}
                for k in self.selected_keys:
                    req = self._build_one(k, p)
                    if req:
                        sub[f"{pt}:{k}:{label}"] = req
                if sub:
                    out[label] = sub
            return out if out else None
        out = {}
        for k in self.selected_keys:
            req = self._build_one(k, payload)
            if req:
                out[f"{pt}:{k}"] = req
        return out if out else None
    # -------- sender helper --------
    def send(self, req, quiet: bool = False, tries_override: int = None): # NEW param
        # Retry + backoff
        transient = {429, 502, 503, 504}
        tries = tries_override if tries_override is not None else 3 # NEW
        backoff = 0.6
        last_err = None
        for attempt in range(1, tries + 1):
            try:
                if req["method"].upper() == "GET":
                    r = self.session.get(
                        req["url"], headers=req.get("headers"),
                        cookies=req.get("cookies"), timeout=self.timeout
                    )
                else:
                    r = self.session.post(
                        req["url"], data=req.get("data"),
                        headers=req.get("headers"), cookies=req.get("cookies"),
                        timeout=self.timeout
                    )
                if r.status_code in transient and attempt < tries:
                    time.sleep(backoff * attempt)
                    continue
                return r
            except Exception as e:
                last_err = e
                if attempt < tries:
                    time.sleep(backoff * attempt)
                    continue
                if not quiet:
                    print(f"[-] Send failed (final): {e} | {req.get('method')} {req.get('url')}")
                return None
# ------------------- Playwright helpers -------------------
def open_in_browser(req):
    if not PW_AVAILABLE:
        print("[-] Playwright not available. Install with: pip install playwright && playwright install")
        return
    def cookie_list_from_req(url, cookies_dict):
        if not cookies_dict:
            return []
        domain = urlparse(url).hostname or ""
        return [{"name": k, "value": v, "domain": domain, "path": "/"} for k, v in cookies_dict.items()]
    p = sync_playwright().start()
    browser = None
    context = None
    try:
        browser = p.chromium.launch(headless=False)
        context_kwargs = {}
        if req.get("headers"):
            context_kwargs["extra_http_headers"] = req["headers"]
        context = browser.new_context(**context_kwargs)
        if req.get("cookies"):
            cookies = cookie_list_from_req(req["url"], req["cookies"])
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception as e:
                    print(f"[!] Could not add cookies to browser: {e}")
        page = context.new_page()
        try:
            if req["method"].upper() == "GET":
                page.goto(req["url"], timeout=30000)
            else:
                resp = page.request.post(req["url"], data=req.get("data") or {})
                txt = resp.text()
                status = resp.status
                page.set_content(f"<pre>Status: {status}\n\n{escape_html(txt)}</pre>")
        except Exception as e:
            page.set_content(f"<pre>Navigation error:\n{escape_html(str(e))}</pre>")
        input("\nPress Enter to close it : ")
    finally:
        try:
            if context:
                context.close()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass
        try:
            p.stop()
        except Exception:
            pass
# ------------------- Browser selection helper -------------------
def prompt_open_results_in_browser(last_prepared: dict):
    if not PW_AVAILABLE:
        print("[*] Playwright not installed; skipping browser open.")
        return
    if not last_prepared:
        print("[*] Nothing to open.")
        return
    keys = list(last_prepared.keys())
    while True:
        print("\nOpen which results in browser?")
        for i, k in enumerate(keys, start=1):
            print(f"{i}. {k}")
        print("Enter indices (e.g., 1,3-5 or 'all') or 0 to stop.")
        sel = input("> ").strip()
        if sel in ("0", "۰", ""):
            return
        try:
            indices = parse_multi_indices(sel, len(keys))
        except Exception:
            print("[-] Invalid selection.")
            continue
        if not indices:
            print("[-] Nothing selected.")
            continue
        for i in indices:
            label = keys[i-1]
            print(f"\n[Playwright] Opening: {label}")
            open_in_browser(last_prepared[label])
        while True:
            cont = input("Open more? (y/n): ").strip().lower()
            yes_set = {"y", "yes", "1", "۱", "ب", "غ"}
            no_set = {"n", "no", "0", "۰", "ن", "د"}
            if cont in yes_set:
                break
            if cont in no_set or cont == "":
                return
            print("Please answer y/n .")
# ------------------- app loop -------------------
def main():
    ic = None
    last_prepared = {} # label -> request dict
    last_responses = {} # label -> response body
    def ensure_ic():
        nonlocal ic
        while ic is None:
            try:
                url = input("Enter target URL: ").strip()
                ic = InputCollector(url)
            except Exception as e:
                print(f"[-] {e}")
                ic = None
    while True:
        print("\n==== Main Menu ====")
        print("1) Set/Change Target URL")
        print("2) Select Target Type & Inputs (multi-select, with Back)")
        print("3) Prepare Requests (single payload) [supports {placeholders}]")
        print("4) Prepare Requests (dict payloads) [supports {placeholders}]")
        print("5) Send Last Prepared (all, via requests) [then optionally open in browser]")
        print("6) Open in Browser (Playwright) one/many of last prepared")
        print("16) Toggle Injection Mode (append/replace) [current: {}]".format(getattr(ic, "injection_mode", "append") if ic else "append"))
        print("17) Toggle Cookie Encode Mode (auto/encode/raw) [current: {}]".format(getattr(ic, "encode_cookies", "auto") if ic else "auto"))
        print("18) Toggle Header Encode Mode (auto/encode/raw) [current: {}]".format(getattr(ic, "encode_headers", "auto") if ic else "auto"))
        print("19) Toggle Context Mode (raw/json/xml/html/js) [current: {}]".format(getattr(ic, "context_mode", "raw") if ic else "raw"))
        print("20) Preview Transform of a payload on a selected input")
        print("9) Exit")
        choice = input("> ").strip()
        if choice in ("9", "۹"):
            print("Bye.")
            break
        if choice in ("1", "۱"):
            ic = None
            ensure_ic()
            continue
        if choice in ("2", "۲"):
            ensure_ic()
            while True:
                tt = ic.choose_target_type()
                if tt is None:
                    print("[*] Cancelled.")
                    break
                if tt == "back":
                    print("[*] Back to main menu.")
                    break
                res = ic.collect_inputs()
                if res == "back":
                    print("[*] Back one step.")
                    continue
                if res is True:
                    print("[+] Inputs ready.")
                    break
                print("[-] Nothing prepared. Try again.")
            continue
        if choice in ("3", "۳"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            raw = input("Enter payload string (e.g., ' or '||(SELECT '' FROM {table})||' ): ").strip()
            if not raw:
                print("[-] Empty payload.")
                continue
            expanded = expand_single_payload_string(raw)
            if not expanded:
                print("[-] No expanded payloads.")
                continue
            prepared = {}
            for label, s in expanded.items():
                built = ic.prepare_injection(s)
                if not built:
                    print(f"[-] Prepare failed for {label}")
                    continue
                prepared.update(built)
            if not prepared:
                print("[-] Prepare failed.")
                continue
            last_prepared.clear(); last_prepared.update(prepared)
            print("\n[Prepared requests]")
            for k, v in last_prepared.items():
                print(k, "->", v)
            continue
        if choice in ("4", "۴"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            print("Enter dict payloads (label:payload), one per line. Empty line to end.")
            raw_dict = {}
            while True:
                line = input()
                if not line.strip(): break
                if ":" not in line:
                    print("Use format label:payload")
                    continue
                label, p = line.split(":", 1)
                raw_dict[label.strip()] = p.strip()
            if not raw_dict:
                print("[-] No payloads provided.")
                continue
            expanded_dict = expand_payload_dict(raw_dict)
            if not expanded_dict:
                print("[-] No expanded payloads.")
                continue
            prepared = ic.prepare_injection(expanded_dict)
            if not prepared:
                print("[-] Prepare failed.")
                continue
            last_prepared.clear()
            for label, group in prepared.items():
                last_prepared.update(group)
            print("\n[Prepared requests]")
            for k, v in last_prepared.items():
                print(k, "->", v)
            continue
        if choice in ("5", "۵"):
            if not last_prepared:
                print("[-] Nothing prepared to send.")
                continue
            ensure_ic()
            last_responses.clear()
            print("\n[Sending prepared requests...]")
            for idx, (label, req) in enumerate(last_prepared.items(), start=1):
                print(f"\n[{idx}] sending {label}")
                r, dt = timed_send(ic, req)
                if r is not None:
                    body = r.text or ""
                    print(f"[+] status={r.status_code}, len={len(body)} hash={_short_hash(body)} time={dt:.3f}s")
                    last_responses[label] = body
                else:
                    print("[!] request failed")
            prompt_open_results_in_browser(last_prepared)
            continue
        if choice in ("6", "۶"):
            if not last_prepared:
                print("[-] Nothing prepared to open.")
                continue
            prompt_open_results_in_browser(last_prepared)
            continue
        if choice in ("16", "۱۶"):
            ensure_ic()
            ic.injection_mode = "replace" if ic.injection_mode == "append" else "append"
            print(f"[*] injection_mode -> {ic.injection_mode}")
            continue
        if choice in ("17", "۱۷"):
            ensure_ic()
            order = ["auto", "encode", "raw"]
            cur = getattr(ic, "encode_cookies", "auto")
            nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "auto"
            ic.encode_cookies = nxt
            print(f"[*] encode_cookies -> {ic.encode_cookies}")
            continue
        if choice in ("18", "۱۸"):
            ensure_ic()
            order = ["auto", "encode", "raw"]
            cur = getattr(ic, "encode_headers", "auto")
            nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "auto"
            ic.encode_headers = nxt
            print(f"[*] encode_headers -> {ic.encode_headers}")
            continue
        if choice in ("19", "۱۹"):
            ensure_ic()
            print("Context modes: 1) raw 2) json 3) xml 4) html 5) js")
            sel = input("> ").strip()
            mapping = {"1":"raw","2":"json","3":"xml","4":"html","5":"js"}
            ic.set_context_mode(mapping.get(sel, "raw"))
            continue
        if choice in ("20", "۲۰"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            keys = ic.selected_keys[:]
            print("\nSelected inputs:")
            for i, k in enumerate(keys, 1):
                print(f"{i}. {k}")
            try:
                idx = to_int_safe(input("Pick input index to preview: "), 1, len(keys)) - 1
            except Exception:
                print("[-] Invalid index.")
                continue
            kname = keys[idx]
            payload = input("Enter a RAW payload to preview: ").strip()
            if not payload:
                print("[-] Empty payload.")
                continue
            prev = ic.preview_transform(kname, payload)
            print("\n[Preview]")
            print("RAW :", prev["RAW"])
            print("CTX :", prev["CTX"], f" (context={ic.context_mode})")
            print("FINAL :", prev["FINAL"])
            continue
        print("[-] Invalid choice.")
        continue
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")