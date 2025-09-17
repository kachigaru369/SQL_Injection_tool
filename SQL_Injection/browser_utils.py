from utils import to_int_safe, parse_multi_indices

# Improved import with better error message
PW_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PW_AVAILABLE = True
    print("[*] Playwright imported successfully")
except ImportError as e:
    print(f"[-] Playwright import failed: {e}")
    print("Install with: pip install playwright && playwright install")
except Exception as e:
    print(f"[-] Unexpected error importing Playwright: {e}")

def prompt_open_results_in_browser(prepared_requests):
    if not PW_AVAILABLE:
        print("[-] Playwright not available. Install with: pip install playwright && playwright install")
        return
    if not prepared_requests:
        print("[-] No prepared requests to open.")
        return

    print("\n[Open in Browser]")
    print("1. Open ALL prepared requests")
    print("2. Open specific request(s)")
    print("9. Back")
    sel = input("> ").strip()
    if sel in ("9", "۹"):
        return
    if sel not in ("1", "2"):
        print("[-] Invalid choice.")
        return

    keys = list(prepared_requests.keys())
    if sel == "2":
        print("\nAvailable requests:")
        for i, k in enumerate(keys, start=1):
            print(f"{i}. {k}")
        print("Select one/many (e.g., 1,3-4 or 'all')")
        sel2 = input("Indices: ").strip()
        try:
            indices = parse_multi_indices(sel2, len(keys))
            keys = [keys[i-1] for i in indices]
        except Exception:
            print("[-] Invalid selection.")
            return
        if not keys:
            print("[-] Nothing selected.")
            return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        for k in keys:
            req = prepared_requests[k]
            page = context.new_page()
            try:
                if req["method"].upper() == "GET":
                    page.goto(req["url"], wait_until="domcontentloaded")
                else:
                    print(f"[*] Opening POST request {k} as GET (browser limitation)")
                    page.goto(req["url"], wait_until="domcontentloaded")
                print(f"[*] Opened {k}")
                input("Press Enter to close this page...")
                page.close()
            except Exception as e:
                print(f"[-] Failed to open {k}: {e}")
        browser.close()