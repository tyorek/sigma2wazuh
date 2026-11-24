#!/usr/bin/env python3
"""sigma2wazuh: convert a curated set of Sigma rules into Wazuh XML rules, using pySigma to parse them.

P6 (2026-11-23). pySigma has no Wazuh backend, so this walks pySigma's parsed condition tree itself:

  1. pySigma parses each rule and resolves the condition (selections, 1 of / all of, modifiers) into a tree of
     AND / OR / NOT nodes over field = value expressions.
  2. The tree is rewritten into disjunctive normal form (an OR of ANDs). Each AND becomes one Wazuh rule, since a Wazuh
     rule can only AND its fields. A Sigma rule that expands to more than MAX_CONJUNCTS Wazuh rules is skipped.
  3. Within one AND, every value test on the same field becomes one PCRE2 expression with lookaheads, so
     "a AND b AND NOT c" on CommandLine is still a single <field> tag. Sigma matching is case-insensitive, so every
     expression starts with (?i). Keywords (no field) become one <match> on the full log.
  4. Fields are mapped per log source (Windows eventchannel, NPM access logs). Anything that can't be mapped or
     expressed is skipped and listed in the report, never approximated.

Usage:  sigma2wazuh.py --config sigma2wazuh.yml --out sigma_rules.xml --report report.md [--tests tests.jsonl]
"""
import argparse, json, re, sys, glob, os, datetime
import yaml
from sigma.rule import SigmaRule
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.types import SigmaString, SigmaNumber, SigmaRegularExpression, SigmaNull, SpecialChars, SigmaCIDRExpression, SigmaExpansion
import ipaddress

MAX_CONJUNCTS = 6
STATIC_FIELDS = {"srcip", "dstip", "srcport", "dstport", "protocol", "action", "id", "url", "data", "extra_data",
                 "status", "system_name", "srcuser", "dstuser", "user"}
LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 11, "critical": 13}


EXTRA_MITRE, MITRE_MAP, MITRE_MAP_PARENTS, LOCAL_FILTERS = {}, {}, set(), {}


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------- log source profiles

def win_field(f):
    special = {"EventID": "win.system.eventID", "Provider_Name": "win.system.providerName",
               "Channel": "win.system.channel", "Computer": "win.system.computer", "Level": "win.system.level"}
    if f in special:
        return special[f]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", f):
        raise Unsupported(f"field {f!r}")
    return "win.eventdata." + f[0].lower() + f[1:]


NPM_FIELDS = {"cs-uri-query": "url", "cs-uri-stem": "url", "cs-uri": "url", "c-uri": "url", "c-uri-query": "url",
              "c-uri-stem": "url", "c-useragent": "npm.useragent", "cs-user-agent": "npm.useragent", "cs-method": "protocol", "sc-status": "id",
              "cs-host": "npm.host"}

PROFILES = {
    # Windows eventchannel: Wazuh lowercases the first letter of every eventdata key (TargetUserName -> targetUserName)
    # Attached with if_group windows: Wazuh makes the rule a child of every rule in the "windows" group, so it is tried
    # at whatever depth the built-in Windows tree stops (60001 -> 60103 -> 60106 ...). Wazuh never backtracks to a
    # sibling once a child matches, and tests on 2026-11-24 showed the built-in grouping rules claim events first, so a
    # Sigma rule under 60000 or 60001 alone never saw most events. Wazuh matches if_group as a substring of a rule's
    # group list, so these rules must not carry any group containing "windows" (an earlier build used "sigma_windows",
    # which made them children of each other; the rule tree never finished building).
    "windows": {
        "parent": "<if_group>windows</if_group>",
        "field": win_field,
        "service_channel": {"security": "Security", "system": "System", "application": "Application"},
        "groups": "sigma_win,",
    },
    # Nginx Proxy Manager access logs (decoder npm-access-fields, base rule 100520)
    "npm": {
        "parent": "<if_sid>100520</if_sid>",
        "field": lambda f: NPM_FIELDS.get(f) or (_ for _ in ()).throw(Unsupported(f"field {f!r}")),
        "service_channel": {},
        "groups": "sigma_web,",
    },
}


def profile_for(ls):
    if ls.product == "windows":
        return "windows"
    if ls.category in ("webserver", "proxy"):
        return "npm"
    raise Unsupported(f"log source {ls}")


# ---------------------------------------------------------------- values -> regex bodies (unanchored)

def value_body(v):
    """Regex body that must match the WHOLE field value (anchoring is added by the caller)."""
    if isinstance(v, SigmaString):
        out = []
        for part in v.s:
            if isinstance(part, str):
                out.append(re.escape(part))
            elif part == SpecialChars.WILDCARD_MULTI:
                out.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                out.append(".")
            else:
                raise Unsupported(f"special char {part}")
        return "".join(out)
    if isinstance(v, SigmaNumber):
        return re.escape(str(v.number))
    if isinstance(v, SigmaRegularExpression):
        rx = v.regexp
        # Sigma regexes are searches; wrap so the whole-value framing still works
        return f".*(?:{rx}).*"
    if isinstance(v, SigmaNull):
        return ""
    if isinstance(v, SigmaExpansion):             # e.g. windash: -x, /x, ...
        return "(?:" + "|".join(value_body(x) for x in v.values) + ")"
    if isinstance(v, SigmaCIDRExpression):
        return cidr_body(str(v.network))
    raise Unsupported(f"value type {type(v).__name__}")


def cidr_body(net):
    n = ipaddress.ip_network(net, strict=False)
    if n.version == 4:
        # expand to octet-aligned subnets, then one alternation of literal prefixes
        step = ((n.prefixlen + 7) // 8) * 8
        subs = list(n.subnets(new_prefix=step)) if step > n.prefixlen else [n]
        if len(subs) > 256:
            raise Unsupported(f"cidr {net} too wide")
        alts = []
        for sn in subs:
            octs = str(sn.network_address).split(".")[: sn.prefixlen // 8]
            alts.append(re.escape(".".join(octs) + ("." if len(octs) < 4 else "")) + (".*" if len(octs) < 4 else ""))
        return "(?:" + "|".join(alts) + ")"
    if n.prefixlen == 128:
        return re.escape(str(n.network_address))
    if str(n) == "fc00::/7":
        return "f[cd][0-9a-f]{2}:.*"
    if str(n) == "fe80::/10":
        return "fe[89ab][0-9a-f]:.*"
    if n.prefixlen % 16 == 0 and n.prefixlen <= 64:
        groups = n.exploded.split(":")[: n.prefixlen // 16]
        return re.escape(":".join(g.lstrip("0") or "0" for g in groups) + ":") + ".*"
    raise Unsupported(f"cidr {net}")


def keyword_body(v):
    if isinstance(v, SigmaString):
        b = value_body(v)
        return b
    raise Unsupported(f"keyword type {type(v).__name__}")


# ---------------------------------------------------------------- condition -> DNF

def dnf(node):
    """Return a list of conjuncts; each conjunct is a list of literals (kind, field, body, negated)."""
    if isinstance(node, ConditionAND):
        acc = [[]]
        for a in node.args:
            sub = dnf(a)
            acc = [x + y for x in acc for y in sub]
            if len(acc) > 64:
                raise Unsupported("condition too large")
        return acc
    if isinstance(node, ConditionOR):
        same = same_field_values(node)
        if same:
            return [[("field", same[0], same[1], False)]]
        out = []
        for a in node.args:
            out += dnf(a)
        return out
    if isinstance(node, ConditionNOT):
        return negate(node.args[0])
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[("field", node.field, value_body(node.value), False)]]
    if isinstance(node, ConditionValueExpression):
        return [[("kw", None, keyword_body(node.value), False)]]
    raise Unsupported(f"condition node {type(node).__name__}")


def same_field_values(node):
    """An OR whose children all test the same field becomes one literal with an alternation."""
    args = node.args
    if args and all(isinstance(a, ConditionFieldEqualsValueExpression) for a in args) and len({a.field for a in args}) == 1:
        return args[0].field, "(?:" + "|".join(value_body(a.value) for a in args) + ")"
    if args and all(isinstance(a, ConditionValueExpression) for a in args):
        return None
    return None


def negate(node):
    if isinstance(node, ConditionAND):          # NOT(a AND b) = NOT a OR NOT b
        out = []
        for a in node.args:
            out += negate(a)
        return out
    if isinstance(node, ConditionOR):           # NOT(a OR b) = NOT a AND NOT b
        same = same_field_values(node)
        if same:
            return [[("field", same[0], same[1], True)]]
        acc = [[]]
        for a in node.args:
            sub = negate(a)
            acc = [x + y for x in acc for y in sub]
            if len(acc) > 64:
                raise Unsupported("negated condition too large")
        return acc
    if isinstance(node, ConditionNOT):
        return dnf(node.args[0])
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[("field", node.field, value_body(node.value), True)]]
    if isinstance(node, ConditionValueExpression):
        return [[("kw", None, keyword_body(node.value), True)]]
    raise Unsupported(f"condition node {type(node).__name__}")


def combine(pos, neg, anchored=True):
    """One PCRE2 expression: every positive body must match the whole value, no negative body may."""
    end = "$" if anchored else ""
    lead = "" if anchored else ".*"
    if len(pos) == 1 and not neg:
        return f"(?i)^{lead}(?:{pos[0]}){end}" if anchored else f"(?i)(?:{pos[0]})"
    parts = [f"(?=(?:{lead}{p}){end})" for p in pos]
    if neg:
        parts.append(f"(?!(?:{lead}(?:{'|'.join(neg)})){end})")
    return "(?i)^" + "".join(parts)


# ---------------------------------------------------------------- one Sigma rule -> Wazuh rule XML strings

def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def convert(path, raw, rule_id_start, prof_name):
    prof = PROFILES[prof_name]
    rule = SigmaRule.from_yaml(raw)
    meta = yaml.safe_load(raw)
    if len(rule.detection.parsed_condition) != 1:
        raise Unsupported("multiple conditions")
    tree = rule.detection.parsed_condition[0].parse()
    conj = dnf(tree)
    if len(conj) > MAX_CONJUNCTS:
        raise Unsupported(f"{len(conj)} alternatives (max {MAX_CONJUNCTS})")
    level = LEVELS.get(str(rule.level.name if rule.level else "medium").lower(), 8)
    tags = meta.get("tags") or []
    mitre = {t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", t)}
    mitre |= set(EXTRA_MITRE.get(str(rule.id), []))
    mitre = sorted({MITRE_MAP.get(m, MITRE_MAP.get(m.split(".")[0], m)) if m.split(".")[0] in MITRE_MAP_PARENTS else m for m in mitre})
    chan = prof["service_channel"].get((rule.logsource.service or "").lower())
    title = xml_escape(meta.get("title", os.path.basename(path)))
    out, tests, rid = [], [], rule_id_start
    for c in conj:
        fields, kpos, kneg = {}, [], []
        for kind, f, body, negd in c:
            if kind == "kw":
                (kneg if negd else kpos).append(body)
                continue
            wf = prof["field"](f)
            d = fields.setdefault(wf, {"pos": [], "neg": []})
            d["neg" if negd else "pos"].append(body)
        # site-specific exclusions from the config (whole-value regex bodies, added as extra negations)
        for lf in LOCAL_FILTERS.get(str(rule.id), []):
            fields.setdefault(lf["field"], {"pos": [], "neg": []})["neg"].append(lf["regex"])
        if not any(d["pos"] for d in fields.values()) and not kpos:
            raise Unsupported("an alternative with only negations")
        lines = [f'  <rule id="{rid}" level="{level}">', f"    {prof['parent']}"]
        if chan and "win.system.channel" not in fields:
            lines.append(f'    <field name="win.system.channel">^{chan}$</field>')
        for wf, d in fields.items():
            # static (decoder-order) fields have their own tags in Wazuh rules; everything else is <field name=...>
            open_t, close_t = (f"<{wf}", f"</{wf}>") if wf in STATIC_FIELDS else (f'<field name="{wf}"', "</field>")
            if d["pos"]:
                rx = combine(d["pos"], d["neg"])
                lines.append(f'    {open_t} type="pcre2">{xml_escape(rx)}{close_t}')
            else:
                rx = "(?i)^(?:" + "|".join(d["neg"]) + ")$"
                lines.append(f'    {open_t} type="pcre2" negate="yes">{xml_escape(rx)}{close_t}')
        if kpos or kneg:
            rx = combine(kpos, kneg, anchored=False)
            lines.append(f'    <match type="pcre2">{xml_escape(rx)}</match>')
        lines.append(f"    <description>Sigma: {title}</description>")
        if mitre:
            lines.append("    <mitre>" + "".join(f"<id>{m}</id>" for m in mitre) + "</mitre>")
        lines.append(f"    <group>sigma,{prof['groups']}</group>")
        lines.append("  </rule>")
        out.append(f"  <!-- {rule.id} | {os.path.relpath(path)} | status {meta.get('status')} -->\n" + "\n".join(lines))
        tests.append({"rule_id": rid, "sigma_id": str(rule.id), "profile": prof_name, "channel": chan,
                      "fields": {k: v["pos"] for k, v in fields.items() if v["pos"]}, "keywords": kpos})
        rid += 1
    return out, tests, rid, {"title": meta.get("title"), "level": level, "mitre": mitre, "n": len(conj)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--tests")
    a = ap.parse_args()
    cfg = yaml.safe_load(open(a.config))
    EXTRA_MITRE.update(cfg.get("extra_mitre", {}))
    LOCAL_FILTERS.update(cfg.get("local_filters", {}))
    MITRE_MAP.update(cfg.get("mitre_map", {}))
    MITRE_MAP_PARENTS.update(k.split(".")[0] for k in MITRE_MAP)
    root = cfg["sigma_root"]
    rid = cfg["first_rule_id"]
    exclude = set(cfg.get("exclude_ids", []))
    skip_eids = {int(x) for x in cfg.get("skip_event_ids", [])}
    statuses = set(cfg.get("statuses", ["stable", "test"]))
    force = set(cfg.get("include_experimental_ids", []))
    min_level = cfg.get("min_level", "low")
    rules_xml, tests, done, skipped = [], [], [], []
    for pat in cfg["include"]:
        for path in sorted(glob.glob(os.path.join(root, pat), recursive=True)):
            raw = open(path).read()
            try:
                meta = yaml.safe_load(raw)
            except yaml.YAMLError as e:
                skipped.append((path, f"yaml: {e}")); continue
            if not isinstance(meta, dict) or "detection" not in meta:
                continue
            if meta.get("id") in exclude:
                skipped.append((path, "excluded by config")); continue
            if meta.get("status") not in statuses and meta.get("id") not in force:
                skipped.append((path, f"status {meta.get('status')}")); continue
            if LEVELS.get(meta.get("level", "medium"), 8) < LEVELS[min_level]:
                skipped.append((path, f"level {meta.get('level')}")); continue
            ls = meta.get("logsource", {})
            only = cfg.get("only_fields", {}).get(ls.get("category", ""))
            try:
                eids = set()
                for v in meta["detection"].values():
                    if isinstance(v, dict) and "EventID" in v:
                        e = v["EventID"]; eids |= set(e if isinstance(e, list) else [e])
                if eids and eids <= skip_eids:
                    raise Unsupported(f"event IDs {sorted(eids)} are not collected")
                if only:
                    used = set()
                    for v in meta["detection"].values():
                        for m in (v if isinstance(v, list) else [v]):
                            if isinstance(m, dict):
                                used |= {k.split("|")[0] for k in m}
                    if used - set(only):
                        raise Unsupported(f"fields {sorted(used - set(only))} not in only_fields for this category")
                rule = SigmaRule.from_yaml(raw)
                prof = profile_for(rule.logsource)
                x, t, rid2, info = convert(path, raw, rid, prof)
                rules_xml += x; tests += t; done.append((path, info, rid, rid2 - 1)); rid = rid2
            except Unsupported as e:
                skipped.append((path, str(e)))
            except Exception as e:
                skipped.append((path, f"{type(e).__name__}: {e}"))
    stamp = datetime.date.today().isoformat()
    head = (f"<!--\n  Sigma rules converted by sigma2wazuh.py (pySigma {__import__('importlib.metadata').metadata.version('pysigma')}) "
            f"on {stamp} from SigmaHQ commit {cfg.get('sigma_commit','?')}.\n"
            f"  {len(done)} Sigma rules -> {len(rules_xml)} Wazuh rules, IDs {cfg['first_rule_id']}-{rid-1}. Do not edit by hand: change\n"
            "  sigma2wazuh.yml and re-run. Install as /var/ossec/etc/rules/sigma_rules.xml (wazuh:wazuh 660).\n-->\n")
    with open(a.out, "w") as f:
        f.write(head + '<group name="sigma,">\n\n' + "\n\n".join(rules_xml) + "\n\n</group>\n")
    with open(a.report, "w") as f:
        f.write(f"# sigma2wazuh report ({stamp})\n\nConverted {len(done)} Sigma rules into {len(rules_xml)} Wazuh rules; skipped {len(skipped)}.\n\n")
        f.write("## Converted\n\n| Wazuh IDs | Level | ATT&CK | Sigma rule |\n|---|---|---|---|\n")
        for p, info, r1, r2 in done:
            ids = str(r1) if r1 == r2 else f"{r1}-{r2}"
            f.write(f"| {ids} | {info['level']} | {' '.join(info['mitre'])} | {info['title']} (`{os.path.basename(p)}`) |\n")
        f.write("\n## Skipped\n\n| Sigma rule | Why |\n|---|---|\n")
        for p, why in skipped:
            f.write(f"| `{os.path.relpath(p, root)}` | {why} |\n")
    if a.tests:
        with open(a.tests, "w") as f:
            for t in tests:
                f.write(json.dumps(t) + "\n")
    print(f"converted {len(done)} sigma rules -> {len(rules_xml)} wazuh rules; skipped {len(skipped)}")


if __name__ == "__main__":
    main()
