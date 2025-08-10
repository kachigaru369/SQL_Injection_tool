import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

class InputCollector:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.response = self.session.get(url)
        self.method = None
        self.target_type = None
        self.selected_key = None
        self.original_value = None
        self.prepared_data = None

    def choose_target_type(self):
        print("\nSelect target to test:")
        print("1. URL Parameter")
        print("2. POST Field")
        print("3. Cookie")
        print("4. Header")
        choice = int(input("Your choice: "))
        self.target_type = choice

    def collect_inputs(self):
        if self.target_type == 1:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            if not params:
                print("No URL parameters found.")
                return
            print("\nURL Parameters:")
            for i, key in enumerate(params.keys(), start=1):
                print(f"{i}. {key} = {params[key]}")
            idx = int(input("Select parameter to inject: ")) - 1
            self.selected_key = list(params.keys())[idx]
            self.original_value = params[self.selected_key][0]
            self.prepared_data = {"type": "url", "params": params, "parsed": parsed}

        elif self.target_type == 2:
            post_data = input("Enter POST data (key1=value1&key2=value2): ")
            fields = dict(pair.split("=") for pair in post_data.split("&"))
            for i, key in enumerate(fields.keys(), start=1):
                print(f"{i}. {key} = {fields[key]}")
            idx = int(input("Select POST field to inject: ")) - 1
            self.selected_key = list(fields.keys())[idx]
            self.original_value = fields[self.selected_key]
            self.prepared_data = {"type": "post", "fields": fields}

        elif self.target_type == 3:
            cookies_dict = self.session.cookies.get_dict()
            if not cookies_dict:
                print("No cookies found in session.")
                return
            for i, key in enumerate(cookies_dict.keys(), start=1):
                print(f"{i}. {key} = {cookies_dict[key]}")
            idx = int(input("Select cookie to inject: ")) - 1
            self.selected_key = list(cookies_dict.keys())[idx]
            self.original_value = cookies_dict[self.selected_key]
            self.prepared_data = {"type": "cookie", "cookies": cookies_dict}

        elif self.target_type == 4:
            default_headers = {"User-Agent": "Mozilla/5.0", "Referer": self.url}
            for i, key in enumerate(default_headers.keys(), start=1):
                print(f"{i}. {key} = {default_headers[key]}")
            idx = int(input("Select header to inject: ")) - 1
            self.selected_key = list(default_headers.keys())[idx]
            self.original_value = default_headers[self.selected_key]
            self.prepared_data = {"type": "header", "headers": default_headers}

    def prepare_injection(self, payload):
        if self.prepared_data["type"] == "url":
            params = self.prepared_data["params"]
            params[self.selected_key] = payload
            new_query = urlencode(params, doseq=True)
            injected_url = urlunparse(self.prepared_data["parsed"]._replace(query=new_query))
            return {"url": injected_url, "method": "GET"}

        elif self.prepared_data["type"] == "post":
            fields = self.prepared_data["fields"]
            fields[self.selected_key] = payload
            return {"url": self.url, "method": "POST", "data": fields}

        elif self.prepared_data["type"] == "cookie":
            cookies = self.prepared_data["cookies"].copy()
            cookies[self.selected_key] = self.original_value + payload
            return {"url": self.url, "method": "GET", "cookies": cookies}

        elif self.prepared_data["type"] == "header":
            headers = self.prepared_data["headers"].copy()
            headers[self.selected_key] = self.original_value + payload
            return {"url": self.url, "method": "GET", "headers": headers}

if __name__ == "__main__":
    url = input("Enter target URL: ")
    ic = InputCollector(url)
    ic.choose_target_type()
    ic.collect_inputs()
    payload = "'"
    request_data = ic.prepare_injection(payload)
    print("\nPrepared request:", request_data)
