import requests
import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote
from utils import to_int_safe, parse_multi_indices, apply_context_escape, looks_encoded

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
            logger.error(f"Preview transform error for {pt}:{key}: {e}")
            final = f"[preview-error] {e}"

        return {"RAW": raw, "CTX": ctx, "FINAL": final}

    def set_context_mode(self, mode: str):
        mode = (mode or "raw").lower()
        if mode not in {"raw", "json", "xml", "html", "js"}:
            logger.warning("Invalid context mode. Using raw.")
            mode = "raw"
        self.context_mode = mode
        logger.info(f"context_mode set to {self.context_mode}")

    def set_url(self, url):
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        self.url = url
        self.response = None
        try:
            self.response = self.session.get(self.url, timeout=self.timeout)
            logger.info(f"Fetched URL with GET: {self.url}")
        except Exception as e:
            logger.error(f"Initial GET failed: {e}")
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
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                logger.warning("No URL parameters found.")
                return None
            print("\nAvailable URL parameters:")
            keys = list(params.keys())
            for i, k in enumerate(keys, start=1):
                print(f"{i}. {k} = {params[k]}")
            print("Select one/many (e.g., 1,3-4 or 'all')")
            sel = input("Indices: ").strip()
            try:
                indices = parse_multi_indices(sel, len(keys))
                self.selected_keys = [keys[i-1] for i in indices]
                self.original_values = {k: params[k][0] for k in self.selected_keys}
                self.prepared_data = {"type": "url", "parsed": parsed, "params": params}
                logger.info(f"Selected URL parameters: {self.selected_keys}")
                return True
            except Exception as e:
                logger.error(f"Error selecting URL parameters: {e}")
                return None

        elif self.target_type == 2:
            if not HAS_BS4:
                logger.error("BeautifulSoup not installed. Install with: pip install beautifulsoup4")
                return None
            if not self.response or not self.response.text:
                logger.error("No response available. Fetch URL first.")
                return None
            soup = BeautifulSoup(self.response.text, 'html.parser')
            forms = soup.find_all('form')
            if not forms:
                logger.warning("No forms found in the page.")
                return None
            print("\nAvailable forms:")
            for i, form in enumerate(forms, start=1):
                action = form.get('action', self.url)
                method = form.get('method', 'POST').upper()
                print(f"{i}. {method} {action}")
            sel_form = input("Select form (index or 0 to cancel): ").strip()
            if sel_form == "0":
                return None
            try:
                form_idx = int(sel_form) - 1
                form = forms[form_idx]
            except:
                logger.error("Invalid form selection.")
                return None
            inputs = form.find_all('input')
            fields = {inp.get('name'): inp.get('value', '') for inp in inputs if inp.get('name')}
            if not fields:
                logger.warning("No input fields found in the form.")
                return None
            print("\nAvailable form fields:")
            keys = list(fields.keys())
            for i, k in enumerate(keys, start=1):
                print(f"{i}. {k} = {fields[k]}")
            print("Select one/many (e.g., 1,3-4 or 'all')")
            sel = input("Indices: ").strip()
            try:
                indices = parse_multi_indices(sel, len(keys))
                self.selected_keys = [keys[i-1] for i in indices]
                self.original_values = {k: fields[k] for k in self.selected_keys}
                action_url = urljoin(self.url, form.get('action', ''))
                self.prepared_data = {"type": "post", "fields": fields, "method": form.get('method', 'POST'), "action_url": action_url}
                logger.info(f"Selected form fields: {self.selected_keys}")
                return True
            except Exception as e:
                logger.error(f"Error selecting form fields: {e}")
                return None

        elif self.target_type == 3:
            cookies = self.session.cookies.get_dict()
            if not cookies:
                logger.warning("No cookies found.")
                return None
            print("\nAvailable cookies:")
            keys = list(cookies.keys())
            for i, k in enumerate(keys, start=1):
                print(f"{i}. {k} = {cookies[k]}")
            print("Select one/many (e.g., 1,3-4 or 'all')")
            sel = input("Indices: ").strip()
            try:
                indices = parse_multi_indices(sel, len(keys))
                self.selected_keys = [keys[i-1] for i in indices]
                self.original_values = {k: cookies[k] for k in self.selected_keys}
                self.prepared_data = {"type": "cookie", "cookies": cookies.copy()}
                logger.info(f"Selected cookies: {self.selected_keys}")
                return True
            except Exception as e:
                logger.error(f"Error selecting cookies: {e}")
                return None

        elif self.target_type == 4:
            default_headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive"
            }
            print("\nAvailable headers:")
            keys = list(default_headers.keys())
            for i, k in enumerate(keys, start=1):
                print(f"{i}. {k} = {default_headers[k]}")
            print("Select one/many (e.g., 1,3-4 or 'all')")
            sel = input("Indices: ").strip()
            try:
                indices = parse_multi_indices(sel, len(keys))
                self.selected_keys = [keys[i-1] for i in indices]
                self.original_values = {k: default_headers[k] for k in self.selected_keys}
                self.prepared_data = {"type": "header", "headers": default_headers.copy()}
                logger.info(f"Selected headers: {self.selected_keys}")
                return True
            except Exception as e:
                logger.error(f"Error selecting headers: {e}")
                return None

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
            logger.error(f"Build error for {pt}:{key}: {e}")
            return None

    def prepare_injection(self, payload):
        if not self.prepared_data or not self.selected_keys:
            logger.error("Nothing prepared. Run collect_inputs() first.")
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
                logger.info(f"Sent {req['method']} request to {req['url']}: status={r.status_code}")
                return r
            except Exception as e:
                last_err = e
                if attempt < tries:
                    time.sleep(backoff * attempt)
                    continue
                if not quiet:
                    logger.error(f"Send failed (final): {e} | {req.get('method')} {req.get('url')}")
                return None