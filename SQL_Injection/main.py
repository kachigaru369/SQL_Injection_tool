import sys
import os
import time
import logging
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    ic = None
    last_prepared = {}   # label -> request dict
    last_responses = {}  # label -> response body
    obfuscator = Obfuscator()
    payload_lists = load_custom_payloads()

    def ensure_ic():
        nonlocal ic
        while ic is None:
            try:
                url = input("Enter target URL: ").strip()
                ic = InputCollector(url)
                logger.info(f"Target URL set to {url}")
            except Exception as e:
                logger.error(f"Error setting URL: {e}")
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
            logger.info("Exiting program.")
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
                    logger.info("Target type selection cancelled.")
                    print("[*] Cancelled.")
                    break
                if tt == "back":
                    logger.info("Back to main menu from target type selection.")
                    print("[*] Back to main menu.")
                    break
                res = ic.collect_inputs()
                if res == "back":
                    logger.info("Back one step in input collection.")
                    print("[*] Back one step.")
                    continue
                if res is True:
                    logger.info("Inputs prepared successfully.")
                    print("[+] Inputs ready.")
                    break
                logger.error("No inputs prepared.")
                print("[-] Nothing prepared. Try again.")
            continue

        if choice in ("3", "۳"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                logger.error("No inputs selected for single payload preparation.")
                print("[-] No inputs selected. Use option 2 first.")
                continue
            raw = validate_input("Enter payload string (e.g., ' or '||(SELECT '' FROM {table})||' ): ", "str")
            if not raw:
                logger.error("Empty payload provided.")
                print("[-] Empty payload.")
                continue
            dbms = validate_input("Enter DBMS for obfuscation (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            apply_obf = validate_input("Apply obfuscation? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if apply_obf in ("y", "yes", "1"):
                orig_payload = raw
                raw, applied_tech = obfuscator.obfuscate_advanced(raw, char_budget=50, dbms=dbms)
                logger.info(f"Obfuscated payload: {raw} (techniques: {', '.join(applied_tech)})")
                print(f"[*] Obfuscated payload: {raw}")
                print(f"[*] Techniques applied: {', '.join(applied_tech)}")
                print(f"[*] Length change: {len(raw) - len(orig_payload)} characters")
            expanded = expand_single_payload_string(raw)
            if not expanded:
                logger.error("Payload expansion failed.")
                print("[-] No expanded payloads.")
                continue
            prepared = {}
            for label, s in expanded.items():
                built = ic.prepare_injection(s)
                if not built:
                    logger.error(f"Prepare failed for {label}")
                    print(f"[-] Prepare failed for {label}")
                    continue
                prepared.update(built)
            last_prepared.clear()
            last_prepared.update(prepared)
            logger.info(f"Prepared {len(prepared)} requests")
            print(f"[*] Prepared {len(prepared)} requests")
            continue

        if choice in ("4", "۴"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                logger.error("No inputs selected for dict payload preparation.")
                print("[-] No inputs selected. Use option 2 first.")
                continue
            print("Enter payload dict as JSON (or blank to skip):")
            raw = validate_input("> ", "str")
            if not raw:
                logger.error("Empty payload dict provided.")
                print("[-] Empty dict.")
                continue
            try:
                payload_dict = json.loads(raw)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON: {e}")
                print(f"[-] Invalid JSON: {e}")
                continue
            expanded = expand_payload_dict(payload_dict)
            if not expanded:
                logger.error("Payload dict expansion failed.")
                print("[-] No expanded payloads.")
                continue
            dbms = validate_input("Enter DBMS for obfuscation (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            apply_obf = validate_input("Apply obfuscation to all payloads? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if apply_obf in ("y", "yes", "1"):
                for label in list(expanded.keys()):
                    orig_payload = expanded[label]
                    new_payload, applied_tech = obfuscator.obfuscate_advanced(orig_payload, char_budget=50, dbms=dbms)
                    expanded[label] = new_payload
                    logger.info(f"Obfuscated {label}: {new_payload} (techniques: {', '.join(applied_tech)})")
                    print(f"[*] Obfuscated {label}: {new_payload} ({', '.join(applied_tech)})")
            prepared = ic.prepare_injection(expanded)
            if not prepared:
                logger.error("Prepare failed for payload dict.")
                print("[-] Prepare failed.")
                continue
            last_prepared.clear()
            last_prepared.update(prepared)
            logger.info(f"Prepared {len(prepared)} requests from dict")
            print(f"[*] Prepared {len(prepared)} requests")
            continue

        if choice in ("5", "۵"):
            ensure_ic()
            if not last_prepared:
                logger.error("No prepared requests to send.")
                print("[-] Nothing prepared. Use option 3 or 4 first.")
                continue
            last_responses.clear()
            for label, req in last_prepared.items():
                r, dt = timed_send(ic, req)
                if r is None:
                    logger.error(f"Send failed for {label}")
                    print(f"[-] {label}: failed")
                    continue
                body = r.text or ""
                last_responses[label] = body
                print(f"[*] {label}: status={r.status_code} len={len(body)} hash={_short_hash(body)} time={dt:.3f}s")
            if last_responses:
                open_browser = validate_input("Open results in browser? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
                if open_browser in ("y", "yes", "1"):
                    prompt_open_results_in_browser(last_prepared)
            continue

        if choice in ("6", "۶"):
            ensure_ic()
            prompt_open_results_in_browser(last_prepared)
            continue

        if choice in ("7", "۷"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                logger.error("No inputs selected for folder payload run.")
                print("[-] No inputs selected. Use option 2 first.")
                continue
            folder = default_folder_input("Enter folder with .py payload files")
            py_files = discover_py_files(folder)
            if not py_files:
                logger.error("No Python files found in folder.")
                print("[-] No .py files found.")
                continue
            mods = []
            for f in py_files:
                mod = load_module_from_path(f)
                if mod:
                    mods.append(mod)
            all_dicts = {}
            for mod in mods:
                all_dicts.update(collect_top_level_dicts(mod))
            if not all_dicts:
                logger.error("No payload dictionaries found in files.")
                print("[-] No payload dictionaries found.")
                continue
            selected_dict = choose_from_list("Select a payload dictionary:", list(all_dicts.keys()))
            if selected_dict in (None, "back"):
                continue
            flat_dict = flatten_payload_dict({selected_dict: all_dicts[selected_dict]})
            expanded = expand_payload_dict(flat_dict)
            if not expanded:
                logger.error("Payload expansion failed.")
                print("[-] No expanded payloads.")
                continue
            dbms = validate_input("Enter DBMS for obfuscation (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            apply_obf = validate_input("Apply obfuscation to all payloads? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if apply_obf in ("y", "yes", "1"):
                for label in list(expanded.keys()):
                    orig_payload = expanded[label]
                    new_payload, applied_tech = obfuscator.obfuscate_advanced(orig_payload, char_budget=50, dbms=dbms)
                    expanded[label] = new_payload
                    logger.info(f"Obfuscated {label}: {new_payload} (techniques: {', '.join(applied_tech)})")
                    print(f"[*] Obfuscated {label}: {new_payload} ({', '.join(applied_tech)})")
            prepared = ic.prepare_injection(expanded)
            if not prepared:
                logger.error("Prepare failed for folder payloads.")
                print("[-] Prepare failed.")
                continue
            last_prepared.clear()
            last_prepared.update(prepared)
            last_responses.clear()
            for label, req in last_prepared.items():
                r, dt = timed_send(ic, req)
                if r is None:
                    logger.error(f"Send failed for {label}")
                    print(f"[-] {label}: failed")
                    continue
                body = r.text or ""
                last_responses[label] = body
                print(f"[*] {label}: status={r.status_code} len={len(body)} hash={_short_hash(body)} time={dt:.3f}s")
            scan_errs = validate_input("Scan for error patterns? (y/n): ", "str", valid_options=["y","n","yes","no","1","0"])
            if scan_errs in ("y", "yes", "1"):
                err_dict = collect_top_level_dicts(load_module_from_path(validate_input("Enter path to error patterns .py file: ", "str")))
                if err_dict:
                    compiled = compile_error_patterns(err_dict)
                    for label, body in last_responses.items():
                        hits = scan_errors(body, compiled)
                        if hits:
                            print(f"[!] {label}: Found errors: {hits}")
            continue

        if choice in ("8", "۸"):
            ensure_ic()
            if not last_responses:
                logger.error("No responses to scan.")
                print("[-] No responses available. Use option 5 or 7 first.")
                continue
            err_dict = collect_top_level_dicts(load_module_from_path(validate_input("Enter path to error patterns .py file: ", "str")))
            if not err_dict:
                logger.error("No error patterns loaded.")
                print("[-] No error patterns loaded.")
                continue
            compiled = compile_error_patterns(err_dict)
            for label, body in last_responses.items():
                hits = scan_errors(body, compiled)
                if hits:
                    print(f"[!] {label}: Found errors: {hits}")
            continue

        if choice in ("10", "۱۰"):
            ensure_ic()
            dbms = validate_input("Enter DBMS (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            attack_type = validate_input("Enter attack type (time-based/error-based/oast/stacked, blank for generic): ", "str", default="generic")
            run_blind_user_payload(ic, obfuscator, dbms=dbms, attack_type=attack_type)
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
            mode = validate_input("Enter injection mode (append/replace): ", "str", valid_options=["append","replace"])
            ic.injection_mode = mode
            logger.info(f"Injection mode set to {mode}")
            print(f"[*] Injection mode set to {mode}")
            continue

        if choice in ("17", "۱۷"):
            ensure_ic()
            mode = validate_input("Enter cookie encode mode (auto/encode/raw): ", "str", valid_options=["auto","encode","raw"])
            ic.encode_cookies = mode
            logger.info(f"Cookie encode mode set to {mode}")
            print(f"[*] Cookie encode mode set to {mode}")
            continue

        if choice in ("18", "۱۸"):
            ensure_ic()
            mode = validate_input("Enter header encode mode (auto/encode/raw): ", "str", valid_options=["auto","encode","raw"])
            ic.encode_headers = mode
            logger.info(f"Header encode mode set to {mode}")
            print(f"[*] Header encode mode set to {mode}")
            continue

        if choice in ("19", "۱۹"):
            ensure_ic()
            mode = validate_input("Enter context mode (raw/json/xml/html/js): ", "str", valid_options=["raw","json","xml","html","js"])
            ic.set_context_mode(mode)
            print(f"[*] Context mode set to {mode}")
            continue

        if choice in ("20", "۲۰"):
            ensure_ic()
            if not ic or not ic.prepared_data or not ic.selected_keys:
                logger.error("No inputs selected for preview.")
                print("[-] No inputs selected. Use option 2 first.")
                continue
            print("\nAvailable inputs:")
            for i, k in enumerate(ic.selected_keys, start=1):
                print(f"{i}. {k}")
            sel = validate_input("Select input index: ", "str")
            try:
                idx = to_int_safe(sel, 1, len(ic.selected_keys)) - 1
                key = ic.selected_keys[idx]
            except:
                logger.error("Invalid input index.")
                print("[-] Invalid index.")
                continue
            payload = validate_input("Enter payload to preview: ", "str")
            if not payload:
                logger.error("Empty payload provided.")
                print("[-] Empty payload.")
                continue
            preview = ic.preview_transform(key, payload)
            print(f"[*] RAW: {preview['RAW']}")
            print(f"[*] CTX: {preview['CTX']}")
            print(f"[*] FINAL: {preview['FINAL']}")
            continue

        if choice in ("21", "۲۱"):
            print("\nCurrent obfuscation settings:")
            print(f"DBMS: {obfuscator.dbms}")
            print(f"Default intensity: {obfuscator.default_intensity}")
            new_dbms = validate_input("Enter DBMS (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank to keep): ", "str", default=obfuscator.dbms)
            new_intensity = validate_input("Enter default intensity (0.0-1.0, blank to keep): ", "float", default=obfuscator.default_intensity)
            obfuscator.dbms = new_dbms
            obfuscator.default_intensity = new_intensity
            logger.info(f"Obfuscation settings updated: DBMS={new_dbms}, intensity={new_intensity}")
            print(f"[*] Updated: DBMS={new_dbms}, intensity={new_intensity}")
            continue

        if choice in ("22", "۲۲"):
            payload = validate_input("Enter payload to obfuscate: ", "str")
            if not payload:
                logger.error("Empty payload provided.")
                print("[-] Empty payload.")
                continue
            dbms = validate_input("Enter DBMS (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            new_payload, applied_tech = obfuscator.obfuscate_advanced(payload, char_budget=50, dbms=dbms)
            logger.info(f"Obfuscated payload: {new_payload} (techniques: {', '.join(applied_tech)})")
            print(f"[*] Obfuscated payload: {new_payload}")
            print(f"[*] Techniques applied: {', '.join(applied_tech)}")
            continue

        if choice in ("23", "۲۳"):
            payload = validate_input("Enter payload to generate variants for: ", "str")
            if not payload:
                logger.error("Empty payload provided.")
                print("[-] Empty payload.")
                continue
            count = validate_input("Number of variants [5]: ", "int", default="5")
            dbms = validate_input("Enter DBMS (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/generic, blank for generic): ", "str", default="generic")
            variants = obfuscator.generate_variants(payload, count=count, dbms=dbms)
            for v in variants:
                print(f"[*] Variant {v['label']}: {v['payload']} (techniques: {', '.join(v['techniques'])})")
            continue

        if choice in ("24", "۲۴"):
            if not last_responses:
                logger.error("No responses to save.")
                print("[-] No responses to save.")
                continue
            filename = validate_input("Enter filename for results [results.json]: ", "str", default="results.json")
            save_results(last_responses, filename)
            continue

        if choice in ("25", "۲۵"):
            print("\nManage Custom Payload Lists:")
            print("1) List all payload lists")
            print("2) Create new payload list")
            print("3) Edit existing payload list")
            print("4) Delete payload list")
            print("9) Back")
            sub_choice = validate_input("> ", "str", valid_options=["1","2","3","4","9"])
            if sub_choice == "9":
                continue
            if sub_choice == "1":
                if not payload_lists["lists"]:
                    logger.error("No payload lists available.")
                    print("[-] No payload lists available.")
                    continue
                for name, data in payload_lists["lists"].items():
                    print(f"\nList: {name}")
                    print(f"  DBMS: {', '.join(data['metadata']['dbms'])}")
                    print(f"  Type: {data['metadata']['type']}")
                    print(f"  Payloads ({len(data['payloads'])}):")
                    for p in data["payloads"]:
                        print(f"    {p}")
                continue
            if sub_choice == "2":
                list_name = validate_input("Enter list name: ", "str")
                if not list_name:
                    logger.error("List name cannot be empty.")
                    print("[-] List name cannot be empty.")
                    continue
                if list_name in payload_lists["lists"]:
                    logger.error("List name already exists.")
                    print("[-] List name already exists.")
                    continue
                dbms = validate_input("Enter DBMS for list (comma-separated, e.g., MySQL,PostgreSQL, blank for all): ", "str", default="")
                attack_type = validate_input("Enter attack type (time-based/error-based/oast/stacked, blank for generic): ", "str", default="")
                print("Enter payloads (one per line, empty to end):")
                payloads = []
                while True:
                    p = validate_input("> ", "str")
                    if not p:
                        break
                    payloads.append(p)
                if not payloads:
                    logger.error("No payloads provided.")
                    print("[-] No payloads provided.")
                    continue
                payload_lists["lists"][list_name] = {
                    "payloads": payloads,
                    "metadata": {
                        "dbms": dbms.split(",") if dbms else ["generic"],
                        "type": attack_type or "generic"
                    }
                }
                save_custom_payloads(payload_lists)
                logger.info(f"Created list '{list_name}' with {len(payloads)} payloads.")
                print(f"[*] Created list '{list_name}' with {len(payloads)} payloads.")
                continue
            if sub_choice == "3":
                list_names = list(payload_lists["lists"].keys())
                if not list_names:
                    logger.error("No payload lists available.")
                    print("[-] No payload lists available.")
                    continue
                chosen_list = choose_from_list("Select a payload list to edit:", list_names)
                if chosen_list in (None, "back"):
                    continue
                print(f"\nCurrent payloads in '{chosen_list}':")
                for i, p in enumerate(payload_lists["lists"][chosen_list]["payloads"], 1):
                    print(f"{i}. {p}")
                print("\n1) Add payloads")
                print("2) Remove payloads")
                print("3) Replace all payloads")
                print("4) Edit metadata")
                print("9) Back")
                edit_choice = validate_input("> ", "str", valid_options=["1", "2", "3", "4", "9"])
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
                        payload_lists["lists"][chosen_list]["payloads"].extend(new_payloads)
                        save_custom_payloads(payload_lists)
                        logger.info(f"Added {len(new_payloads)} payloads to '{chosen_list}'.")
                        print(f"[*] Added {len(new_payloads)} payloads to '{chosen_list}'.")
                elif edit_choice == "2":
                    print("Enter indices to remove (e.g., 1,3-4):")
                    indices = parse_multi_indices(validate_input("> ", "str"), len(payload_lists["lists"][chosen_list]["payloads"]))
                    if not indices:
                        logger.error("No valid indices provided.")
                        print("[-] No valid indices provided.")
                        continue
                    payload_lists["lists"][chosen_list]["payloads"] = [p for i, p in enumerate(payload_lists["lists"][chosen_list]["payloads"], 1) if i not in indices]
                    save_custom_payloads(payload_lists)
                    logger.info(f"Removed {len(indices)} payloads from '{chosen_list}'.")
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
                        logger.error("No payloads provided.")
                        print("[-] No payloads provided.")
                        continue
                    payload_lists["lists"][chosen_list]["payloads"] = new_payloads
                    save_custom_payloads(payload_lists)
                    logger.info(f"Replaced payloads in '{chosen_list}' with {len(new_payloads)} new payloads.")
                    print(f"[*] Replaced payloads in '{chosen_list}' with {len(new_payloads)} new payloads.")
                elif edit_choice == "4":
                    dbms = validate_input("Enter DBMS for list (comma-separated, e.g., MySQL,PostgreSQL, blank for all): ", "str", default="")
                    attack_type = validate_input("Enter attack type (time-based/error-based/oast/stacked, blank for generic): ", "str", default="")
                    payload_lists["lists"][chosen_list]["metadata"] = {
                        "dbms": dbms.split(",") if dbms else ["generic"],
                        "type": attack_type or "generic"
                    }
                    save_custom_payloads(payload_lists)
                    logger.info(f"Updated metadata for '{chosen_list}'.")
                    print(f"[*] Updated metadata for '{chosen_list}'.")
                continue
            if sub_choice == "4":
                list_names = list(payload_lists["lists"].keys())
                if not list_names:
                    logger.error("No payload lists available.")
                    print("[-] No payload lists available.")
                    continue
                chosen_list = choose_from_list("Select a payload list to delete:", list_names)
                if chosen_list in (None, "back"):
                    continue
                del payload_lists["lists"][chosen_list]
                save_custom_payloads(payload_lists)
                logger.info(f"Deleted list '{chosen_list}'.")
                print(f"[*] Deleted list '{chosen_list}'.")
                continue

        logger.error("Invalid menu choice.")
        print("[-] Invalid choice.")
        continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Program interrupted by user.")
        print("\n[!] Interrupted.")