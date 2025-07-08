from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException
from bs4 import BeautifulSoup
import time

# ========== تنظیمات ==========
options = Options()
# اگه می‌خوای مرورگر باز شه خط پایین رو کامنت کن
options.headless = False
driver = webdriver.Firefox(options=options)

# ========== ورود آدرس ==========
url = input("Enter full page URL: ").strip()
driver.get(url)
time.sleep(2)

# ========== استخراج فرم‌ها ==========
soup = BeautifulSoup(driver.page_source, "html.parser")
forms = soup.find_all("form")
if not forms:
    print("[-] No forms found.")
    driver.quit()
    exit()

print(f"\n[+] Found {len(forms)} forms.")
for i, form in enumerate(forms):
    print(f"\nForm #{i+1}")
    print("  Action:", form.get("action"))
    print("  Method:", form.get("method", "GET").upper())
    inputs = form.find_all(["input", "textarea", "select"])
    for input_tag in inputs:
        input_name = input_tag.get("name")
        if not input_name:
            continue
        input_type = input_tag.get("type", "text") if input_tag.name == "input" else input_tag.name
        print(f"    - {input_tag.name}: type = {input_type}, name = {input_name}")
    print("-" * 40)

# ========== انتخاب فرم ==========
try:
    choice = int(input(f"\n[?] Enter form number to use (1–{len(forms)}): "))
    if choice < 1 or choice > len(forms):
        print("[-] Invalid form number.")
        driver.quit()
        exit()
except ValueError:
    print("[-] Invalid input.")
    driver.quit()
    exit()

selected_form = forms[choice - 1]
input_names = [tag.get("name") for tag in selected_form.find_all(["input", "textarea", "select"]) if tag.get("name")]

# ========== پر کردن فیلدها در صفحه ==========
for name in input_names:
    try:
        element = driver.find_element(By.NAME, name)
        if element.get_attribute("type") in ["hidden", "submit"]:
            continue  # مقدار خودش ست شده
        user_input = input(f"[+] Enter value for '{name}': ")
        element.clear()
        element.send_keys(user_input)
    except:
        print(f"[-] Could not fill: {name}")

# ========== ارسال فرم ==========
try:
    driver.find_element(By.TAG_NAME, "form").submit()
except:
    print("[-] Submit failed.")
    driver.quit()
    exit()

time.sleep(2)

# ========== کلیک روی Back to blog (اختیاری) ==========
try:
    back_button = driver.find_element(By.LINK_TEXT, "Back to blog")
    back_button.click()
    time.sleep(2)
except:
    print("[*] No 'Back to blog' button found.")

# ========== بررسی اجرای XSS ==========
try:
    alert = driver.switch_to.alert
    print(f"[!!!] ALERT EXECUTED: {alert.text} ✅ (XSS Confirmed)")
    alert.dismiss()
except:
    print("[*] No alert detected.")

# ========== پایان ==========
# اگه نمی‌خوای مرورگر بسته شه، این خط رو کامنت کن
# driver.quit()
