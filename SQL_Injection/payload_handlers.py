import re
import itertools
import importlib.util
import os
from utils import to_int_safe, parse_multi_indices, validate_input

PLACEHOLDER_RX = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

def find_placeholders_in_string(s: str):
    return list(dict.fromkeys(PLACEHOLDER_RX.findall(str(s) or "")))

def find_placeholders_in_dict(d: dict):
    found = []
    for v in d.values():
        found += find_placeholders_in_string(v)
    out = []
    for x in found:
        if x not in out:
            out.append(x)
    return out

def parse_list_or_single(prompt_txt: str):
    """
    Input:
      - "abc" -> ["abc"]
      - "[a,b,c]" -> ["a","b","c"]
      - "" -> []
    """
    raw = input(prompt_txt).strip()
    if not raw:
        return []
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1]
        items = [i.strip() for i in inner.split(",") if i.strip() != ""]
        return items
    return [raw]

def expand_one_payload_string(s: str, var_map: dict):
    vars_in = find_placeholders_in_string(s)
    if not vars_in:
        return [("", s)]
    lists = []
    for v in vars_in:
        vals = var_map.get(v, [])
        if not vals:
            print(f"[!] No value provided for placeholder {{{v}}}, skipping this payload.")
            return []
        lists.append([(v, val) for val in vals])
    combos = list(itertools.product(*lists))
    out = []
    for combo in combos:
        filled = s
        parts = []
        for (vn, vv) in combo:
            filled = filled.replace("{"+vn+"}", str(vv))
            parts.append(f"{vn}={vv}")
        label_suffix = "|".join(parts)
        out.append((label_suffix, filled))
    return out

def expand_payload_dict(payload_dict: dict):
    vars_all = find_placeholders_in_dict(payload_dict)
    var_map = {}
    for v in vars_all:
        vals = parse_list_or_single(f"Value(s) for placeholder {{{v}}} (single or [a,b,c]): ")
        if not vals:
            print(f"[!] No values entered for {{{v}}}. This var will be skipped in expansions.")
        var_map[v] = vals

    expanded = {}
    for label, s in payload_dict.items():
        variants = expand_one_payload_string(s, var_map)
        if not variants:
            continue
        for label_suffix, filled in variants:
            new_label = label if not label_suffix else f"{label}|{label_suffix}"
            expanded[new_label] = filled
    return expanded

def expand_single_payload_string(s: str, max_combinations=1000):
    vars_in = find_placeholders_in_string(s)
    if not vars_in:
        return {"p0": s}
    var_map = {}
    for v in vars_in:
        vals = parse_list_or_single(f"Value(s) for placeholder {{{v}}} (single or [a,b,c]): ")
        if not vals:
            print(f"[!] No values entered for {{{v}}}. Skipping.")
            return {}
        var_map[v] = vals
    out = {}
    for label_suffix, filled in expand_one_payload_string(s, var_map):
        new_label = "p0" if not label_suffix else f"p0|{label_suffix}"
        out[new_label] = filled
    # محدود کردن تعداد ترکیب‌ها
    if len(out) > max_combinations:
        out = dict(list(out.items())[:max_combinations])
        print(f"[*] Limited to {max_combinations} combinations.")
    return out

def discover_py_files(folder: str):
    out = []
    for root, dirs, files in os.walk(folder):
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out

def load_module_from_path(path: str):
    name = f"dynmod_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        print(f"[-] Failed to load {path}: {e}")
        return None

def collect_top_level_dicts(mod):
    result = {}
    for k, v in vars(mod).items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            result[k] = v
    return result

def choose_from_list(title, items):
    print(f"\n{title}")
    for i, it in enumerate(items, start=1):
        print(f"{i}. {it}")
    print("9. Back   |   0. Cancel")
    sel = input("> ").strip()
    if sel in ("9", "۹"): return "back"
    if sel in ("0", "۰"): return None
    try:
        idx = to_int_safe(sel, 1, len(items)) - 1
    except Exception:
        print("[-] Invalid selection.")
        return None
    return items[idx]

def flatten_payload_dict(payload_dict):
    flat = {}
    for key, val in payload_dict.items():
        if isinstance(val, list):
            for i, v in enumerate(val):
                flat[f"{key}[{i}]"] = str(v)
        else:
            flat[str(key)] = str(val)
    return flat

def compile_error_patterns(err_dict):
    comp = {}
    for engine, patterns in err_dict.items():
        c = []
        for p in patterns:
            try:
                c.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error as e:
                print(f"[!] Invalid regex for {engine}: {p} ({e})")
        if c:
            comp[engine] = c
    return comp

def scan_errors(text: str, compiled_errs):
    hits = []
    for engine, regs in compiled_errs.items():
        for r in regs:
            m = r.search(text or "")
            if m:
                hits.append({"engine": engine, "pattern": r.pattern})
    return hits