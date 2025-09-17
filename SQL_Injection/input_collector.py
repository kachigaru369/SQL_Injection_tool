import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote
from utils import to_int_safe, parse_multi_indices, apply_context_escape, looks_encoded

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False

class InputCollector:
    def __init__(self, url, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.injection_mode = "append"
        self.encode_cookies = "auto"
        self.encode_headers = "auto"
        self.set_url(url)
        self.context_mode = "raw"

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
                    base_params = dict(parse_qs(parsed.query, keep_blank_values=True))
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
            if choice == 0:
                return None
            if choice == 9:
                return "back"
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
        print("Select one/many (e.g., 1,3-4 or 'all')  |  9: Back  |  0: Cancel")
        sel = input("Indices: ").strip()
        if sel in ("9", "۹"):
            return "back"
        if sel in ("0", "۰"):
            return False
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
                if not name:
                    continue
                value = inp.get("value", "")
                fields[name] = value
            for ta in f.find_all("textarea"):
                name = ta.get("name")
                if not name:
                    continue
                value = ta.text or ""
                fields[name] = value
            for sel in f.find_all("select"):
                name = sel.get("name")
                if not name:
                    continue
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

        print("Pick a form (number)  |  9: Back  |  0: Cancel")
        sel = input("> ").strip()
        if sel in ("9", "۹"):
            return "back"
        if sel in ("0", "۰"):
            return False
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
        print("Select one/many (e.g., 1,2-3 or 'all')  |  9: Back  |  0: Cancel")
        sel2 = input("Indices: ").strip()
        if sel2 in ("9", "۹"):
            return "back"
        if sel2 in ("0", "۰"):
            return False
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
        print("Select one/many (e.g., 1,3-4 or 'all')  |  9: Back  |  0: Cancel")
        sel = input("Indices: ").strip()
        if sel in ("9", "۹"):
            return "back"
        if sel in ("0", "۰"):
            return False
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
            print("Select one/many (e.g., 1,2 or 'all')  |  8: Add custom  |  9: Back  |  0: Cancel")
            sel = input("Indices: ").strip()
            if sel in ("9", "۹"):
                return "back"
            if sel in ("0", "۰"):
                return False
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

    def _build_one(self, key, payload_str):
        pt = self.prepared_data["type"]
        p = str(payload_str)
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
                    base_params = dict(parse_qs(parsed.query, keep_blank_values=True))
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

    def send(self, req, quiet: bool = False, tries_override: int = None):
        transient = {429, 502, 503, 504}
        tries = tries_override if tries_override is not None else 3
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