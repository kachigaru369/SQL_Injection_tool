import sys
import os
import time
from input_collector import InputCollector
from obfuscator import Obfuscator
from blind_runner import run_blind_user_payload
from db_helpers import (
    run_column_counter,
    run_datatype_tester,
    run_version_probe,
    run_db_info_interactive,
    run_column_counter_advanced
)
from browser_utils import prompt_open_results_in_browser
from payload_handlers import (
    expand_single_payload_string,
    expand_payload_dict,
    flatten_payload_dict,
    discover_py_files,
    load_module_from_path,
    collect_top_level_dicts,
    choose_from_list,
    compile_error_patterns,
    scan_errors
)
from utils import to_int_safe, parse_multi_indices, timed_send, _short_hash, default_folder_input, save_results, validate_input, load_custom_payloads, save_custom_payloads

def main():
    ic = None
    last_prepared = {}   # label -> request dict
    last_responses = {}  # label -> response body
    obfuscator = Obfuscator()

    def ensure_ic():
        nonlocal ic
        while ic is None:
            try:
                url = input("Enter target URL: ").strip()
                ic = InputCollector(url)
            except Exception as e:
                print(f"[-] {e}")
                ic = None

    while True:
        print("\n==== Main Menu ====")
        print("1) Set/Change Target URL")
        print("2) Select Target Type & Inputs (multi-select, with Back)")
        print("3) Prepare Requests (single payload)  [supports {placeholders}]")
        print("4) Prepare Requests (dict payloads)   [supports {placeholders}]")
        print("5) Send Last Prepared (all, via requests)  [then optionally open in browser]")
        print("6) Open in Browser (Playwright) one/many of last prepared")
        print("7) Load & Run Payload Dicts from Folder (auto, optional error-scan) [supports {placeholders}]")
        print("8) Load Error Regex Dicts & Scan Last Responses")
        print("9) Exit")
        print("10) Blind (user-provided payloads) on selected inputs [supports {placeholders}]")
        print("11) Column Count Helper (ORDER BY / UNION NULL)")
        print("12) Data Type Tester (per column)")
        print("13) DB Version Probe (UNION)")
        print("14) DB Info Interactive (UNION builder)")
        print("15) Column Count Helper (Advanced, multi-DBMS, CAST/Time/Boolean-friendly)")
        print("16) Toggle Injection Mode (append/replace)  [current: {}]".format(getattr(ic, "injection_mode", "append") if ic else "append"))
        print("17) Toggle Cookie Encode Mode (auto/encode/raw)  [current: {}]".format(getattr(ic, "encode_cookies", "auto") if ic else "auto"))
        print("18) Toggle Header Encode Mode (auto/encode/raw)  [current: {}]".format(getattr(ic, "encode_headers", "auto") if ic else "auto"))
        print("19) Toggle Context Mode (raw/json/xml/html/js)  [current: {}]".format(getattr(ic, "context_mode", "raw") if ic else "raw"))
        print("20) Preview Transform of a payload on a selected input")
        print("21) Configure Obfuscation Settings")
        print("22) Apply Obfuscation to Payload")
        print("23) Generate Multiple Obfuscated Variants")
        print("24) Save Last Results to File")
        print("25) Manage Custom Payload Lists (custom_payloads.json)")
        choice = validate_input("> ", "str", valid_options=["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","۱","۲","۳","۴","۵","۶","۷","۸","۹","۱۰","۱۱","۱۲","۱۳","۱۴","۱۵","۱۶","۱۷","۱۸","۱۹","۲۰","۲۱","۲۲","۲۳","۲۴","۲۵"])

        if choice in ("9", "۹"):
            print("Bye.")
            break

        if choice in ("1", "۱"):
            ic = None
            ensure_ic()
            continue

        if choice in ("2", "۲"):
            ensure_ic()
            while True:
                tt = ic.choose_target_type()
                if tt is None:
                    print("[*] Cancelled.")
                    break
                if tt == "back":
                    print("[*] Back to main menu.")
                    break
                res = ic.collect_inputs()
                if res == "back":
                    print("[*] Back one step.")
                    continue
                if res is True:
                    print("[+] Inputs ready.")
                    break
                print("[-] Nothing prepared. Try again.")
            continue

        if choice in ("3", "۳"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            raw = validate_input("Enter payload string (e.g., ' or '||(SELECT '' FROM {table})||' ): ", "str")
            if not raw:
                print("[-] Empty payload.")
                continue
            apply_obf = validate_input("Apply obfuscation? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if apply_obf in ("y", "yes", "1"):
                orig_payload = raw
                raw, applied_tech = obfuscator.obfuscate_advanced(raw, char_budget=50)
                print(f"[*] Obfuscated payload: {raw}")
                print(f"[*] Techniques applied: {', '.join(applied_tech)}")
                print(f"[*] Length change: {len(raw) - len(orig_payload)} characters")
            expanded = expand_single_payload_string(raw)
            if not expanded:
                print("[-] No expanded payloads.")
                continue
            prepared = {}
            for label, s in expanded.items():
                built = ic.prepare_injection(s)
                if not built:
                    print(f"[-] Prepare failed for {label}")
                    continue
                prepared.update(built)
            if not prepared:
                print("[-] Prepare failed.")
                continue
            last_prepared.clear()
            last_prepared.update(prepared)
            print("\n[Prepared requests]")
            for k, v in last_prepared.items():
                print(k, "->", v)
            continue

        if choice in ("4", "۴"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            print("Enter dict payloads (label:payload), one per line. Empty line to end.")
            raw_dict = {}
            while True:
                line = validate_input("> ", "str")
                if not line:
                    break
                if ":" not in line:
                    print("Use format label:payload")
                    continue
                label, p = line.split(":", 1)
                raw_dict[label.strip()] = p.strip()
            if not raw_dict:
                print("[-] No payloads provided.")
                continue
            apply_obf = validate_input("Apply obfuscation to all payloads? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if apply_obf in ("y", "yes", "1"):
                for label, val in list(raw_dict.items()):
                    new_val, applied_tech = obfuscator.obfuscate_advanced(val, char_budget=50)
                    raw_dict[label] = new_val
                    print(f"[*] Obfuscated {label}: {new_val}  (tech: {', '.join(applied_tech)})")
            expanded_dict = expand_payload_dict(raw_dict)
            if not expanded_dict:
                print("[-] No expanded payloads.")
                continue
            prepared = ic.prepare_injection(expanded_dict)
            if not prepared:
                print("[-] Prepare failed.")
                continue
            last_prepared.clear()
            for label, group in prepared.items():
                last_prepared.update(group)
            print("\n[Prepared requests]")
            for k, v in last_prepared.items():
                print(k, "->", v)
            continue

        if choice in ("5", "۵"):
            if not last_prepared:
                print("[-] Nothing prepared to send.")
                continue
            ensure_ic()
            last_responses.clear()
            results = []
            print("\n[Sending prepared requests...]")
            for idx, (label, req) in enumerate(last_prepared.items(), start=1):
                print(f"\n[{idx}] sending {label}")
                r, dt = timed_send(ic, req)
                result = {
                    "label": label,
                    "status_code": r.status_code if r else None,
                    "body_length": len(r.text) if r and r.text else None,
                    "body_hash": _short_hash(r.text) if r and r.text else None,
                    "time": dt
                }
                results.append(result)
                if r is not None:
                    body = r.text or ""
                    print(f"[+] status={r.status_code}, len={len(body)} hash={_short_hash(body)} time={dt:.3f}s")
                    last_responses[label] = body
                else:
                    print("[!] request failed")
            prompt_open_results_in_browser(last_prepared)
            save_results(results, f"results_{int(time.time())}.json")
            continue

        if choice in ("6", "۶"):
            if not last_prepared:
                print("[-] Nothing prepared to open.")
                continue
            prompt_open_results_in_browser(last_prepared)
            continue

        if choice in ("7", "۷"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            folder = default_folder_input("Enter payloads folder (blank = this program directory, or give subfolder name): ")
            if not os.path.isdir(folder):
                print("[-] Not a directory.")
                continue
            pyfiles = discover_py_files(folder)
            if not pyfiles:
                print("[-] No .py files found.")
                continue
            chosen_file = choose_from_list("Pick a .py file:", pyfiles)
            if chosen_file in (None, "back"):
                continue
            mod = load_module_from_path(chosen_file)
            if not mod:
                continue
            dicts_map = collect_top_level_dicts(mod)
            if not dicts_map:
                print("[-] No top-level dicts in this module.")
                continue
            dict_names = list(dicts_map.keys())
            chosen_dict_name = choose_from_list("Pick a dict name to use as payloads:", dict_names)
            if chosen_dict_name in (None, "back"):
                continue
            payload_dict_raw = dicts_map[chosen_dict_name]
            flat_payloads = flatten_payload_dict(payload_dict_raw)
            expanded = expand_payload_dict(flat_payloads)
            if not expanded:
                print("[-] No expanded payloads.")
                continue
            prepared = ic.prepare_injection(expanded)
            if not prepared:
                print("[-] Prepare failed.")
                continue
            want_err = validate_input("Load error regex dicts from another folder for scanning? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            compiled_errs = None
            if want_err in ("y", "yes", "1"):
                err_folder = default_folder_input("Enter errors folder (blank = this program directory, or give subfolder name): ")
                if os.path.isdir(err_folder):
                    pyfiles2 = discover_py_files(err_folder)
                    if pyfiles2:
                        chosen_file2 = choose_from_list("Pick a .py file (errors):", pyfiles2)
                        if chosen_file2 not in (None, "back"):
                            mod2 = load_module_from_path(chosen_file2)
                            if mod2:
                                dicts_map2 = collect_top_level_dicts(mod2)
                                if dicts_map2:
                                    err_name = choose_from_list("Pick a dict name (errors):", list(dicts_map2.keys()))
                                    if err_name not in (None, "back"):
                                        compiled_errs = compile_error_patterns(dicts_map2[err_name])
            last_prepared.clear()
            for label, group in prepared.items():
                last_prepared.update(group)
            results = []
            print("\n[Sending prepared batch...]")
            last_responses.clear()
            for idx, (lbl, req) in enumerate(last_prepared.items(), start=1):
                print(f"\n[{idx}] sending {lbl}")
                r, dt = timed_send(ic, req)
                result = {
                    "label": lbl,
                    "status_code": r.status_code if r else None,
                    "body_length": len(r.text) if r and r.text else None,
                    "body_hash": _short_hash(r.text) if r and r.text else None,
                    "time": dt
                }
                results.append(result)
                if r is not None:
                    body = r.text or ""
                    print(f"[+] status={r.status_code}, len={len(body)} hash={_short_hash(body)} time={dt:.3f}s")
                    if compiled_errs:
                        matches = scan_errors(body, compiled_errs)
                        if matches:
                            print("[ERR-MATCH] Found patterns:")
                            result["errors"] = [{"engine": m["engine"], "pattern": m["pattern"]} for m in matches]
                            for m in matches:
                                print(f"  - {m['engine']}: {m['pattern']}")
                        else:
                            print("[ERR-MATCH] No regex hits.")
                    last_responses[lbl] = body
                else:
                    print("[!] request failed")
            prompt_open_results_in_browser(last_prepared)
            save_results(results, f"batch_results_{int(time.time())}.json")
            continue

        if choice in ("8", "۸"):
            if not last_responses:
                print("[-] No responses to scan. Send requests first.")
                continue
            folder = default_folder_input("Enter errors folder (blank = this program directory, or give subfolder name): ")
            if not os.path.isdir(folder):
                print("[-] Not a directory.")
                continue
            pyfiles = discover_py_files(folder)
            if not pyfiles:
                print("[-] No .py files found.")
                continue
            chosen_file = choose_from_list("Pick a .py file (errors):", pyfiles)
            if chosen_file in (None, "back"):
                continue
            mod = load_module_from_path(chosen_file)
            if not mod:
                continue
            dicts_map = collect_top_level_dicts(mod)
            if not dicts_map:
                print("[-] No dicts found.")
                continue
            chosen_dict_name = choose_from_list("Pick a dict name (errors):", list(dicts_map.keys()))
            if chosen_dict_name in (None, "back"):
                continue
            compiled = compile_error_patterns(dicts_map[chosen_dict_name])
            print("\n[Scanning last responses...]")
            for lbl, body in last_responses.items():
                hits = scan_errors(body, compiled)
                if hits:
                    print(f"\n{lbl}:")
                    for h in hits:
                        print(f"  - {h['engine']}: {h['pattern']}")
                else:
                    print(f"\n{lbl}: no regex hits.")
            continue

        if choice in ("10", "۱۰"):
            ensure_ic()
            run_blind_user_payload(ic, obfuscator)
            continue

        if choice in ("11", "۱۱"):
            ensure_ic()
            run_column_counter(ic)
            continue

        if choice in ("12", "۱۲"):
            ensure_ic()
            run_datatype_tester(ic)
            continue

        if choice in ("13", "۱۳"):
            ensure_ic()
            run_version_probe(ic)
            continue

        if choice in ("14", "۱۴"):
            ensure_ic()
            run_db_info_interactive(ic)
            continue

        if choice in ("15", "۱۵"):
            ensure_ic()
            run_column_counter_advanced(ic)
            continue

        if choice in ("16", "۱۶"):
            ensure_ic()
            ic.injection_mode = "replace" if ic.injection_mode == "append" else "append"
            print(f"[*] injection_mode -> {ic.injection_mode}")
            continue

        if choice in ("17", "۱۷"):
            ensure_ic()
            order = ["auto", "encode", "raw"]
            cur = getattr(ic, "encode_cookies", "auto")
            nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "auto"
            ic.encode_cookies = nxt
            print(f"[*] encode_cookies -> {ic.encode_cookies}")
            continue

        if choice in ("18", "۱۸"):
            ensure_ic()
            order = ["auto", "encode", "raw"]
            cur = getattr(ic, "encode_headers", "auto")
            nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "auto"
            ic.encode_headers = nxt
            print(f"[*] encode_headers -> {ic.encode_headers}")
            continue

        if choice in ("19", "۱۹"):
            ensure_ic()
            print("Context modes: 1) raw  2) json  3) xml  4) html  5) js")
            sel = validate_input("> ", "str", valid_options=["1","2","3","4","5"])
            mapping = {"1":"raw","2":"json","3":"xml","4":"html","5":"js"}
            ic.set_context_mode(mapping.get(sel, "raw"))
            continue

        if choice in ("20", "۲۰"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            keys = ic.selected_keys[:]
            print("\nSelected inputs:")
            for i, k in enumerate(keys, 1):
                print(f"{i}. {k}")
            try:
                idx = to_int_safe(validate_input("Pick input index to preview: ", "int", default="1"), 1, len(keys)) - 1
            except Exception:
                print("[-] Invalid index.")
                continue
            kname = keys[idx]
            payload = validate_input("Enter a RAW payload to preview: ", "str")
            if not payload:
                print("[-] Empty payload.")
                continue
            prev = ic.preview_transform(kname, payload)
            print("\n[Preview]")
            print("RAW   :", prev["RAW"])
            print("CTX   :", prev["CTX"], f"  (context={ic.context_mode})")
            print("FINAL :", prev["FINAL"])
            continue

        if choice in ("21", "۲۱"):
            print("\n=== Obfuscation Configuration ===")
            print("1) Set Target DBMS")
            print("2) View Available Techniques")
            print("3) Set Default Intensity")
            print("4) Set Encoding Policy")
            print("5) Set Safety Rules")
            print("6) Back")
            obf_choice = validate_input("> ", "str", valid_options=["1","2","3","4","5","6"])
            if obf_choice == "1":
                dbms_options = list(obfuscator.dbms_config.keys())
                for i, dbms in enumerate(dbms_options, 1):
                    print(f"{i}. {dbms}")
                try:
                    dbms_sel = to_int_safe(validate_input("Select DBMS: ", "int", default="1"), 1, len(dbms_options))
                    obfuscator.set_dbms(dbms_options[dbms_sel-1])
                    print(f"[*] DBMS set to: {dbms_options[dbms_sel-1]}")
                except:
                    print("[-] Invalid selection")
            elif obf_choice == "2":
                print("\nAvailable Obfuscation Techniques:")
                for i, tech in enumerate(obfuscator.techniques.keys(), 1):
                    print(f"{i}. {tech}")
            elif obf_choice == "3":
                try:
                    intensity = float(validate_input("Intensity (0.0-1.0): ", "float", default="0.5"))
                    if 0.0 <= intensity <= 1.0:
                        obfuscator.default_intensity = intensity
                        print(f"[*] Intensity set to: {intensity}")
                    else:
                        print("[-] Must be between 0.0 and 1.0")
                except:
                    print("[-] Invalid number")
            elif obf_choice == "4":
                print("\nEncoding Policy (comma-separated, e.g., url,html,base64):")
                print("Available: url, html, base64, hex, unicode, double_url")
                policy_input = validate_input("> ", "str", default="")
                if policy_input:
                    policy = [p.strip() for p in policy_input.split(",")]
                    obfuscator.set_encoding_policy(policy)
                    print(f"[*] Encoding policy set to: {policy}")
            elif obf_choice == "5":
                print("\nSafety Rules Configuration:")
                print("1) Toggle token boundary preservation")
                print("2) Set max length increase factor")
                print("3) Back")
                safety_choice = validate_input("> ", "str", valid_options=["1","2","3"])
                if safety_choice == "1":
                    current = obfuscator.safety_rules["preserve_token_boundaries"]
                    obfuscator.safety_rules["preserve_token_boundaries"] = not current
                    print(f"[*] Token boundary preservation: {obfuscator.safety_rules['preserve_token_boundaries']}")
                elif safety_choice == "2":
                    try:
                        factor = float(validate_input("Max length increase factor (e.g., 2.0): ", "float", default="2.0"))
                        obfuscator.safety_rules["max_length_increase"] = factor
                        print(f"[*] Max length increase factor set to: {factor}")
                    except:
                        print("[-] Invalid number")
            continue

        if choice in ("22", "۲۲"):
            payload = validate_input("Enter payload to obfuscate: ", "str")
            if not payload:
                print("[-] Empty payload")
                continue
            print("\nSelect techniques (comma-separated, or 'all'):")
            techniques = list(obfuscator.techniques.keys())
            for i, tech in enumerate(techniques, 1):
                print(f"{i}. {tech}")
            tech_sel = validate_input("> ", "str", default="all")
            selected_techs = []
            if tech_sel.lower() in ("all", "*"):
                selected_techs = techniques
            else:
                try:
                    indices = parse_multi_indices(tech_sel, len(techniques))
                    selected_techs = [techniques[i-1] for i in indices]
                except:
                    print("[-] Invalid selection, using all")
                    selected_techs = techniques
            try:
                intensity = float(validate_input("Intensity (0.0-1.0) [0.5]: ", "float", default="0.5"))
            except:
                intensity = 0.5
            obfuscated, applied = obfuscator.obfuscate(payload, selected_techs, intensity)
            print(f"\nOriginal: {payload}")
            print(f"Obfuscated: {obfuscated}")
            print(f"Techniques applied: {', '.join(applied)}")
            continue

        if choice in ("23", "۲۳"):
            payload = validate_input("Enter payload to generate variants: ", "str")
            if not payload:
                print("[-] Empty payload")
                continue
            try:
                count = int(validate_input("Number of variants [5]: ", "int", default="5"))
            except:
                count = 5
            try:
                intensity = float(validate_input("Intensity (0.0-1.0) [0.5]: ", "float", default="0.5"))
            except:
                intensity = 0.5
            variants = obfuscator.generate_variants(payload, count, None, intensity)
            print(f"\nGenerated {len(variants)} variants:")
            for i, variant in enumerate(variants, 1):
                print(f"\n{i}. {variant['payload']}")
                print(f"   Techniques: {', '.join(variant['techniques'])}")
            continue

        if choice in ("24", "۲۴"):
            if not last_responses:
                print("[-] No responses to save.")
                continue
            filename = validate_input("Enter filename to save results (default: results.json): ", "str", default="results.json")
            results = [
                {
                    "label": lbl,
                    "body_length": len(body),
                    "body_hash": _short_hash(body),
                    "time": last_responses.get(lbl, {}).get("time", 0)
                }
                for lbl, body in last_responses.items()
            ]
            save_results(results, filename)
            continue

        if choice in ("25", "۲۵"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                print("[-] No inputs selected. Use option 2 first.")
                continue
            print("\n=== Manage Custom Payload Lists ===")
            print("1) Load and use a payload list")
            print("2) Create a new payload list")
            print("3) Edit an existing payload list")
            print("4) Delete a payload list")
            print("9) Back")
            sub_choice = validate_input("> ", "str", valid_options=["1", "2", "3", "4", "9"])
            if sub_choice == "9":
                continue

            payload_lists = load_custom_payloads()
            if not payload_lists:
                print("[-] No payload lists found. Create one first.")
                if sub_choice != "2":
                    continue

            if sub_choice == "1":
                list_names = list(payload_lists.keys())
                if not list_names:
                    print("[-] No payload lists available.")
                    continue
                chosen_list = choose_from_list("Select a payload list:", list_names)
                if chosen_list in (None, "back"):
                    continue
                payloads = payload_lists[chosen_list]
                raw_dict = {f"{chosen_list}_{i}": p for i, p in enumerate(payloads, 1)}
                apply_obf = validate_input("Apply obfuscation to payloads? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
                if apply_obf in ("y", "yes", "1"):
                    for label, val in list(raw_dict.items()):
                        new_val, applied_tech = obfuscator.obfuscate_advanced(val, char_budget=50)
                        raw_dict[label] = new_val
                        print(f"[*] Obfuscated {label}: {new_val}  (tech: {', '.join(applied_tech)})")
                expanded_dict = expand_payload_dict(raw_dict)
                if not expanded_dict:
                    print("[-] No expanded payloads.")
                    continue
                prepared = ic.prepare_injection(expanded_dict)
                if not prepared:
                    print("[-] Prepare failed.")
                    continue
                last_prepared.clear()
                for label, group in prepared.items():
                    last_prepared.update(group)
                print("\n[Prepared requests]")
                for k, v in last_prepared.items():
                    print(k, "->", v)
                print("[*] You can now use option 5 to send or 10 for blind tests.")
                continue

            if sub_choice == "2":
                list_name = validate_input("Enter list name: ", "str")
                if not list_name:
                    print("[-] List name cannot be empty.")
                    continue
                if list_name in payload_lists:
                    print("[-] List name already exists.")
                    continue
                print("Enter payloads (one per line, empty to end):")
                payloads = []
                while True:
                    p = validate_input("> ", "str")
                    if not p:
                        break
                    payloads.append(p)
                if not payloads:
                    print("[-] No payloads provided.")
                    continue
                payload_lists[list_name] = payloads
                save_custom_payloads(payload_lists)
                print(f"[*] Created list '{list_name}' with {len(payloads)} payloads.")
                continue

            if sub_choice == "3":
                list_names = list(payload_lists.keys())
                if not list_names:
                    print("[-] No payload lists available.")
                    continue
                chosen_list = choose_from_list("Select a payload list to edit:", list_names)
                if chosen_list in (None, "back"):
                    continue
                print(f"\nCurrent payloads in '{chosen_list}':")
                for i, p in enumerate(payload_lists[chosen_list], 1):
                    print(f"{i}. {p}")
                print("\n1) Add payloads")
                print("2) Remove payloads")
                print("3) Replace all payloads")
                print("9) Back")
                edit_choice = validate_input("> ", "str", valid_options=["1", "2", "3", "9"])
                if edit_choice == "9":
                    continue
                if edit_choice == "1":
                    print("Enter new payloads (one per line, empty to end):")
                    new_payloads = []
                    while True:
                        p = validate_input("> ", "str")
                        if not p:
                            break
                        new_payloads.append(p)
                    if new_payloads:
                        payload_lists[chosen_list].extend(new_payloads)
                        save_custom_payloads(payload_lists)
                        print(f"[*] Added {len(new_payloads)} payloads to '{chosen_list}'.")
                elif edit_choice == "2":
                    print("Enter indices to remove (e.g., 1,3-4):")
                    indices = parse_multi_indices(validate_input("> ", "str"), len(payload_lists[chosen_list]))
                    if not indices:
                        print("[-] No valid indices provided.")
                        continue
                    payload_lists[chosen_list] = [p for i, p in enumerate(payload_lists[chosen_list], 1) if i not in indices]
                    save_custom_payloads(payload_lists)
                    print(f"[*] Removed {len(indices)} payloads from '{chosen_list}'.")
                elif edit_choice == "3":
                    print("Enter new payloads (one per line, empty to end):")
                    new_payloads = []
                    while True:
                        p = validate_input("> ", "str")
                        if not p:
                            break
                        new_payloads.append(p)
                    if not new_payloads:
                        print("[-] No payloads provided.")
                        continue
                    payload_lists[chosen_list] = new_payloads
                    save_custom_payloads(payload_lists)
                    print(f"[*] Replaced payloads in '{chosen_list}' with {len(new_payloads)} new payloads.")
                continue

            if sub_choice == "4":
                list_names = list(payload_lists.keys())
                if not list_names:
                    print("[-] No payload lists available.")
                    continue
                chosen_list = choose_from_list("Select a payload list to delete:", list_names)
                if chosen_list in (None, "back"):
                    continue
                del payload_lists[chosen_list]
                save_custom_payloads(payload_lists)
                print(f"[*] Deleted list '{chosen_list}'.")
                continue

        print("[-] Invalid choice.")
        continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")