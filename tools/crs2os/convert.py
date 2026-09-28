"""Convert OWASP CRS seclang rules to an openshield ruleset YAML.

Only rules the *current* engine can express are emitted; everything else is
skipped and tallied in a report. Each SecRule becomes one openshield rule per
target variable, with id `<crs-id>#<target-field>`.
"""
import re, sys, collections, argparse
import msc_pyparser, yaml

CRS_VERSION = "4.29.0"
SEV = {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}
PHASE = {"1": "request_headers", "2": "request_body", "3": "response_headers",
         "4": "response_body", "5": "logging"}

# seclang transform -> openshield function (only those the engine has).
TRANSFORMS = {
    "urlDecodeUni": "url_decode_uni", "lowercase": "lower", "uppercase": "upper",
    "htmlEntityDecode": "html_entity_decode", "utf8toUnicode": "utf8_to_unicode",
    "removeNulls": "remove_nulls", "replaceNulls": "replace_nulls",
    "removeWhitespace": "remove_whitespace", "trim": "trim",
    "trimLeft": "trim_start", "trimRight": "trim_end",
    "base64Decode": "base64_decode", "base64Encode": "base64_encode",
    "hexEncode": "hex_encode", "sha1": "sha1",
    "jsDecode": "js_decode", "cssDecode": "css_decode", "cmdLine": "cmd_line", "removeComments": "remove_comments",
    "replaceComments": "replace_comments", "compressWhitespace": "compress_whitespace",
    "escapeSeqDecode": "escape_seq_decode",
    "normalizePath": "normalize_path", "normalizePathWin": "normalize_path_win",
}

Target = collections.namedtuple("Target", "field is_array")

class Unsupported(Exception):
    pass

def selector_field(base, sel):
    """REQUEST_HEADERS:Name -> http.request.headers["name"] (array via map index)."""
    return Target(f'{base}["{sel.lower()}"]', True)

def targets_for(var, phase):
    v, sel, neg, cnt = var["variable"], var.get("variable_part"), var.get("negated"), var.get("counter")
    if v == "XML":
        return []                                        # out of scope (per decision)
    if neg:
        raise Unsupported(f"negated selector !{v}:{sel}")
    if sel and re.search(r"[/*]", sel):
        raise Unsupported(f"regex/wildcard selector {v}:{sel}")
    body = phase != "request_headers"

    if sel:
        base = {"REQUEST_HEADERS": "http.request.headers",
                "RESPONSE_HEADERS": "http.response.headers",
                "REQUEST_COOKIES": "http.request.cookies",
                "ARGS": "http.request.uri.args"}.get(v)
        if not base:
            raise Unsupported(f"selector on {v}")
        return [selector_field(base, sel)]

    table = {
        "REQUEST_COOKIES":       [Target("http.request.cookies.values", True)],
        "REQUEST_COOKIES_NAMES": [Target("http.request.cookies.names", True)],
        "ARGS":       [Target("http.request.uri.args.values", True)]
                      + ([Target("http.request.body.form.values", True),
                          Target("http.request.body.multipart.values", True)] if body else []),
        "ARGS_NAMES": [Target("http.request.uri.args.names", True)]
                      + ([Target("http.request.body.form.names", True)] if body else []),
        "ARGS_GET":       [Target("http.request.uri.args.values", True)],
        "ARGS_GET_NAMES": [Target("http.request.uri.args.names", True)],
        "REQUEST_HEADERS":       [Target("http.request.headers.values", True)],
        "REQUEST_HEADERS_NAMES": [Target("http.request.headers.names", True)],
        "RESPONSE_HEADERS":      [Target("http.response.headers.values", True)],
        "REQUEST_BODY":     [Target("http.request.body.raw", False)],
        "RESPONSE_BODY":    [Target("http.response.body.raw", False)],
        "REQUEST_FILENAME": [Target("http.request.uri.path", False)],
        "REQUEST_URI":      [Target("http.request.uri", False)],
        "REQUEST_URI_RAW":  [Target("http.request.uri", False)],
        "QUERY_STRING":     [Target("http.request.uri.query", False)],
        "REQUEST_METHOD":   [Target("http.request.method", False)],
        "REQUEST_PROTOCOL": [Target("http.request.version", False)],
        "RESPONSE_STATUS":  [Target("http.response.code", False)],
        "REMOTE_ADDR":      [Target("ip.src", False)],
    }
    if v not in table:
        raise Unsupported(f"variable {v}")
    if cnt:
        # &VAR: count of matching values. Use one target's array length.
        t = table[v][0]
        if not t.is_array:
            raise Unsupported(f"&{v} on scalar")
        return [Target(f"len({t.field})", "count")]
    return table[v]

def fix_pattern(p):
    # wirefilter compiles regexes in byte mode: `\x{HH}` is Unicode-only.
    return re.sub(r"\\x\{([0-9a-fA-F]{1,2})\}", lambda m: "\\x" + m.group(1).zfill(2), p)

CMP = {"@eq": "==", "@gt": ">", "@lt": "<", "@ge": ">=", "@le": "<="}

# Phrase lists collected from @pmFromFile, emitted as `kind: phrases` lists.
PHRASE_LISTS = {}   # list_name -> [phrases]
CRS_DIR = None      # set in main(); rules dir holding the .data files

def load_phrase_file(fname):
    """Load a CRS .data file (one phrase per line, `#` comments) into a list."""
    name = "crs_pm_" + re.sub(r"[^0-9a-z]+", "_", fname.lower()).strip("_")
    if name not in PHRASE_LISTS:
        path = f"{CRS_DIR}/rules/{fname}"
        items = [ln.rstrip("\n") for ln in open(path, encoding="utf-8")
                 if ln.strip() and not ln.lstrip().startswith("#")]
        PHRASE_LISTS[name] = items
    return name
def transformed(source, transforms):
    for t in transforms:
        source = f"{t}({source})"
    return source

def regex_escape(p):
    return re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', p)

def status_range(pattern):
    """An anchored status-code regex -> (lo, hi) numeric range, or None.

    Handles fixed-width patterns of literal digits and `\\d`/`[0-9]` wildcards
    (optionally `{n}`), e.g. `^404$` -> (404, 404), `^5\\d{2}$` -> (500, 599).
    """
    m = re.fullmatch(r"\^(.*)\$", pattern)
    if not m:
        return None
    body, lo, hi = m.group(1), "", ""
    i = 0
    while i < len(body):
        c = body[i]
        if c.isdigit():
            lo += c; hi += c; i += 1
        elif body[i:i + 2] == r"\d" or body[i:i + 5] == "[0-9]":
            i += 2 if body[i] == "\\" else 5
            n = 1
            rep = re.match(r"\{(\d+)\}", body[i:])
            if rep:
                n = int(rep.group(1)); i += rep.end()
            lo += "0" * n; hi += "9" * n
        else:
            return None
    if not lo:
        return None
    return int(lo), int(hi)

def status_predicate(field, op, arg, negated):
    """RESPONSE_STATUS match -> numeric comparison on `http.response.code`."""
    if op in CMP:
        if not re.fullmatch(r"-?\d+", arg or ""):
            raise Unsupported(f"status comparison rhs {arg!r}")
        return f"{field} {CMP[op]} {arg}"
    if op == "@streq" and re.fullmatch(r"\d+", arg or ""):
        return f"{field} {'!=' if negated else '=='} {arg}"
    if op == "@rx":
        rng = status_range(arg)
        if rng is None:
            raise Unsupported(f"unhandled status regex {arg!r}")
        lo, hi = rng
        if lo == hi:
            return f"{field} {'!=' if negated else '=='} {lo}"
        pos = f"{field} >= {lo} and {field} <= {hi}"
        return f"not ({pos})" if negated else f"({pos})"
    raise Unsupported(f"{op} on status code")

def predicate(target, op, arg, transforms, negated):
    """Render one openshield boolean expression for a single target."""
    field = target.field
    if target.is_array == "count":                        # len(...) already
        if op not in CMP:
            raise Unsupported(f"count with {op}")
        if not re.fullmatch(r"-?\d+", arg or ""):
            raise Unsupported(f"non-numeric count rhs {arg!r}")
        return f"{field} {CMP[op]} {arg}"

    # We expose the HTTP status as an integer (`http.response.code`), so a
    # seclang string match on RESPONSE_STATUS is rendered as the idiomatic
    # numeric comparison it really is (e.g. `@rx ^5\d{2}$` -> 500..599).
    if field == "http.response.code":
        return status_predicate(field, op, arg, negated)

    arr = target.is_array
    src = f"{field}[*]" if arr else field
    src = transformed(src, transforms)

    if op == "@rx":
        pat = fix_pattern(arg)
        if '"#' in pat:
            raise Unsupported('pattern contains `"#`')
        inner = f'regex_match({src}, r#"{pat}"#)'
    elif op == "@detectSQLi":
        inner = f"detect_sqli({src})"
    elif op == "@detectXSS":
        inner = f"detect_xss({src})"
    elif op == "@streq":
        inner = f'{src} == "{esc(arg)}"'
    elif op == "@contains":
        inner = f'{src} contains "{esc(arg)}"'
    elif op == "@beginsWith":
        inner = f'starts_with({src}, "{esc(arg)}")'
    elif op == "@endsWith":
        inner = f'ends_with({src}, "{esc(arg)}")'
    elif op in CMP:
        if not re.fullmatch(r"-?\d+", arg or ""):
            raise Unsupported(f"comparison rhs {arg!r}")
        if arr:
            raise Unsupported("numeric comparison on array target")
        return f"{field_sub(src)} {CMP[op]} {arg}"
    elif op == "@ipMatch":
        if arr:
            raise Unsupported("@ipMatch on array")
        ips = " ".join(a.strip() for a in arg.split(","))
        return f"{field} in {{{ips}}}"
    elif op == "@pmFromFile":
        # Substring match against a phrase file -> a `phrases` list. The `in`
        # operator needs [*] on its immediate LHS, so transforms wrap the bare
        # field and [*] comes after the chain.
        if negated:
            raise Unsupported("negated @pmFromFile")
        list_name = load_phrase_file(arg.strip())
        base = transformed(field, transforms)
        return f"any({base}[*] in ${list_name})" if arr else f"{base} in ${list_name}"
    elif op == "@pm":
        # Short inline phrase set -> case-insensitive regex alternation, reusing
        # regex_match (which the regex engine lowers to Aho-Corasick).
        if negated:
            raise Unsupported("negated @pm")
        phrases = arg.split()
        alt = "(?i)" + "|".join(regex_escape(p) for p in phrases)
        if '"#' in alt:
            raise Unsupported('phrase contains `"#`')
        inner = f'regex_match({src}, r#"{alt}"#)'
        return f"any({inner})" if arr else inner
    else:
        raise Unsupported(f"operator {op}")

    if arr:
        expr = f"any({inner})"
        if negated:
            # ModSecurity skips a negated rule when the variable is absent; guard
            # on presence so an empty array doesn't false-positive.
            return f"len({field}) > 0 and not({expr})"
        return expr
    return f"not ({inner})" if negated else inner

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

def field_sub(src):  # numeric comparison target is scalar, no [*]
    return src

def link_scores(acts):
    """Anomaly-score setvars on a (possibly non-head) chain link."""
    scores = []
    for s in acts["setvar"]:
        m = re.fullmatch(r"tx\.(\w+)=\+%\{tx\.(\w+)_anomaly_score\}", s, re.I)
        if not m:
            raise Unsupported(f"setvar {s}")
        scores.append({"name": m.group(1).lower(), "increment": SEV[m.group(2).upper()]})
    return scores

def link_targets_and_op(r, phase):
    """Parse one SecRule (link) into (targets, op, arg, negated, transforms)."""
    acts = collections.defaultdict(list)
    for a in r["actions"]:
        acts[a["act_name"]].append(a["act_arg"])
    for t in acts["t"]:
        if t != "none" and t not in TRANSFORMS:
            raise Unsupported(f"transform {t}")
    transforms = [TRANSFORMS[t] for t in acts["t"] if t != "none"]
    op = r.get("operator")
    negated = bool(r.get("operator_negated"))
    arg = r.get("operator_argument", "") or ""
    if op is None:
        raise Unsupported("no operator")
    if "%{" in arg:
        raise Unsupported("macro in operator argument")
    targets = []
    for v in r["variables"]:
        targets += targets_for(v, phase)
    if not targets:
        raise Unsupported("no supported targets")
    return targets, op, arg, negated, transforms

def link_disjunction(r, phase):
    """One chain link -> `(t1 or t2 or ...)` over its targets, plus its scores."""
    targets, op, arg, negated, transforms = link_targets_and_op(r, phase)
    preds = [predicate(t, op, arg, transforms, negated) for t in targets]
    acts = collections.defaultdict(list)
    for a in r["actions"]:
        acts[a["act_name"]].append(a["act_arg"])
    return " or ".join(preds), link_scores(acts)

def rule_scaffold(head, src_file, scores, action):
    """Common metadata dict from a rule/chain head."""
    acts = collections.defaultdict(list)
    for a in head["actions"]:
        acts[a["act_name"]].append(a["act_arg"])
    one = lambda k, d=None: acts[k][0] if acts[k] else d
    tags = acts["tag"]
    pl = next((t for t in tags if t.startswith("paranoia-level/")), "paranoia-level/1")
    rule = {}
    if one("msg"):
        rule["description"] = one("msg").replace("%{", "{")
    rule["ref"] = (f"https://github.com/coreruleset/coreruleset/blob/"
                   f"v{CRS_VERSION}/rules/{src_file}#L{head['lineno']}")
    if acts["ver"]:
        rule["version"] = one("ver").split("/")[-1]
    rule["categories"] = tags + ([f"severity/{one('severity')}"] if acts["severity"] else [])
    enabled_false = pl != "paranoia-level/1"
    rule["phase"] = PHASE[one("phase", "2")]
    rule["action"] = action
    if scores:
        rule["action_parameters"] = {"scores": scores}
    if acts["nolog"]:
        rule["logging"] = {"enabled": False}
    return rule, enabled_false

def convert_rule(r, src_file):
    acts = collections.defaultdict(list)
    for a in r["actions"]:
        acts[a["act_name"]].append(a["act_arg"])
    if not acts["id"]:
        raise Unsupported("no id (chain link / control rule)")
    if acts["chain"]:
        raise Unsupported("chained rule")

    phase = PHASE[acts["phase"][0] if acts["phase"] else "2"]
    targets, op, arg, negated, transforms = link_targets_and_op(r, phase)
    scores = link_scores(acts)
    action = "score" if scores else ("block" if acts["deny"] else "log")
    base_id = acts["id"][0]

    out = []
    for target in targets:
        expr = predicate(target, op, arg, transforms, negated)
        rule, enabled_false = rule_scaffold(r, src_file, scores, action)
        rule = {"id": f"{base_id}#{target.field}", **rule}
        if enabled_false:
            rule = {**rule, "enabled": False}
        rule["expression"] = expr
        out.append(rule)
    return out

def convert_chain(chain, src_file):
    """A chained rule -> one openshield rule: `and` of each link's disjunction.

    Metadata comes from the head; anomaly scores are collected across all links
    (CRS often puts the setvar on the last link, not the head).
    """
    head = chain[0]
    hacts = collections.defaultdict(list)
    for a in head["actions"]:
        hacts[a["act_name"]].append(a["act_arg"])
    phase = PHASE[hacts["phase"][0] if hacts["phase"] else "2"]

    parts, scores = [], []
    for link in chain:
        expr, sc = link_disjunction(link, phase)
        parts.append(f"({expr})")
        scores.extend(sc)
    action = "score" if scores else ("block" if hacts["deny"] else "log")
    rule, enabled_false = rule_scaffold(head, src_file, scores, action)
    rule = {"id": hacts["id"][0], **rule}
    if enabled_false:
        rule = {**rule, "enabled": False}
    rule["expression"] = " and ".join(parts)
    return [rule]

def has_chain(r):
    return any(a["act_name"] == "chain" for a in r["actions"])

def convert_file(path):
    p = msc_pyparser.MSCParser()
    p.parser.parse(open(path).read())
    src = path.split("/")[-1]
    items = [r for r in p.configlines if r["type"] == "SecRule"]
    rules, skipped = [], []
    i = 0
    while i < len(items):
        r = items[i]
        rid = next((a["act_arg"] for a in r["actions"] if a["act_name"] == "id"), None)
        if has_chain(r):
            # Gather the chain: head + following links until one without `chain`.
            chain = [r]
            j = i + 1
            while j < len(items):
                chain.append(items[j])
                if not has_chain(items[j]):
                    break
                j += 1
            i = j + 1
            try:
                rules.extend(convert_chain(chain, src))
            except Unsupported as e:
                skipped.append((rid, f"chain: {e}"))
            continue
        i += 1
        try:
            rules.extend(convert_rule(r, src))
        except Unsupported as e:
            skipped.append((rid, str(e)))
    return rules, skipped

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("crs_dir")
    ap.add_argument("-o", "--out", default="crs.yaml")
    ap.add_argument("--rule", help="convert only this crs id and print (debug)")
    a = ap.parse_args()

    global CRS_DIR
    CRS_DIR = a.crs_dir

    import glob
    all_rules, all_skipped, reasons = [], [], collections.Counter()
    for f in sorted(glob.glob(f"{a.crs_dir}/rules/*.conf")):
        rules, skipped = convert_file(f)
        all_rules += rules
        for rid, why in skipped:
            all_skipped.append((rid, why))
            reasons[re.sub(r"[:'].*", "", why).strip()] += 1

    if a.rule:
        sel = [r for r in all_rules if r["id"].split("#")[0] == a.rule]
        print(dump(sel)); return

    lists = [{"name": name, "kind": "phrases", "items": items}
             for name, items in sorted(PHRASE_LISTS.items())]
    out_doc = {
        "lists": lists,
        "rulesets": [{
            "name": "owasp-crs",
            "description": f"OWASP Core Rule Set {CRS_VERSION} (auto-converted)",
            "version": CRS_VERSION,
            "scores": sorted({s["name"] for r in all_rules
                              if r["action"] == "score"
                              for s in r["action_parameters"]["scores"]}),
            "rules": all_rules,
        }],
    }
    open(a.out, "w").write(dump(out_doc))

    crs_ids = {rid for rid, _ in all_skipped} | {r["id"].split("#")[0] for r in all_rules}
    print(f"converted {len(all_rules)} openshield rules "
          f"from {len({r['id'].split('#')[0] for r in all_rules})} CRS rules")
    print(f"emitted {len(PHRASE_LISTS)} phrase lists "
          f"({sum(len(v) for v in PHRASE_LISTS.values())} phrases total)")
    print(f"skipped {len(all_skipped)} CRS rules:")
    for why, n in reasons.most_common():
        print(f"  {n:4}  {why}")

def dump(obj):
    class D(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True
    D.add_representer(str, lambda d, s: d.represent_scalar(
        "tag:yaml.org,2002:str", s,
        style="|" if "\n" in s else ("'" if len(s) > 80 or "\\" in s or ":" in s else None)))
    return yaml.dump(obj, Dumper=D, sort_keys=False, width=1000, allow_unicode=True)

if __name__ == "__main__":
    main()
