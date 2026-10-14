#!/usr/bin/env python3
"""chain-screener eval + prompt scorecard (Python stdlib only).

Three components, weighted into one 0-100 score:

  fixture (15)     - all fixture files present, valid JSON, meet minimum counts
  functional (30)  - the offline demo engine reproduces every expected scenario score
  prompt (55)      - the README "Prompt" block specifies everything the evals require

The prompt component is the hill-climb objective: run this, fix the failing
rubric items in the prompt, re-run, keep the gain. Each run is appended to
evals/history.jsonl.

Usage:
    python3 evals/score.py
    python3 evals/score.py --json
    python3 evals/score.py --no-history
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "fixtures"
README = REPO / "README.md"
DEMO = REPO / "demo" / "omnibus_screen.py"
HISTORY = REPO / "evals" / "history.jsonl"

WEIGHTS = {"fixture": 0.15, "functional": 0.30, "prompt": 0.55}

RUBRIC = [
    ("chains", 2, ["ethereum", "arbitrum", "bitcoin"]),
    ("stdlib_only", 2, ["stdlib", "no pip"]),
    ("readonly_secrets", 2, ["read-only", "private key", "never sign"]),
    ("datasources", 2, ["ofac", "opensanctions", "gleif"]),
    ("gleif_warning", 2, ["does not map wallets"]),
    ("normalization", 2, ["eip-55", "bech32"]),
    ("sanctions_fields", 2, ["list_name", "listing_date", "program"]),
    ("edge_schema", 2, ["tx_hash", "asset", "hop"]),
    ("trace_gap", 2, ["trace_", "known_gaps"]),
    ("taint_decay", 2, ["decay", "cycle"]),
    ("bridge", 1, ["bridge", "cross-chain"]),
    ("scoring_bands", 2, ["0-100", "evidence"]),
    ("output_schema", 2, ["risk_score", "risk_band", "truncated", "limits"]),
    ("resilience", 2, ["timeout", "backoff", "cache"]),
    ("determinism", 2, ["byte-identical"]),
    ("definition_of_done", 2, ["passes every eval", "no non-stdlib"]),
    ("omnibus_bank", 3, ["omnibus", "commingled", "counterpart", "sar"]),
    ("human_view", 1, ["mermaid", "graphviz"]),
    ("negative_controls", 1, ["false positive"]),
]

MAX_PROMPT = sum(w for _, w, _ in RUBRIC)


def load_demo():
    spec = importlib.util.spec_from_file_location("omnibus_screen", DEMO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def prompt_block():
    txt = README.read_text()
    m = re.search(r"## 1\. The Prompt.*?```(?:text)?\n(.*?)```", txt, re.S)
    return m.group(1) if m else ""


def fixture_component():
    details, ok = [], True
    spec = {
        "known-tainted.json": {},
        "incidents.json": {"incidents": 10},
        "known-labels.json": {"exchange_wallets": 30},
        "omnibus-cases.json": {"cases": 6},
    }
    for name, mins in spec.items():
        p = FIX / name
        if not p.exists():
            details.append(f"missing {name}")
            ok = False
            continue
        try:
            d = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            details.append(f"{name}: invalid JSON ({e})")
            ok = False
            continue
        for key, minimum in mins.items():
            got = len(d.get(key, []))
            if got < minimum:
                details.append(f"{name}: {key}={got} < {minimum}")
                ok = False
        if not any(x.startswith(name) for x in details):
            details.append(f"{name}: ok")
    return (100 if ok else 0), details


def functional_component():
    mod = load_demo()
    seeds, attr, payload, out_edges, in_edges = mod.build_world()
    passed, total, details = 0, 0, []
    for case in payload["cases"]:
        total += 1
        r = mod.screen(case["omnibus_wallet"]["addr"], seeds, attr, out_edges, in_edges, mod.DEFAULT_MAX_HOPS)
        exp = case["expected"]["risk_score"]
        good = r["score"] == exp
        passed += int(good)
        details.append(f"{case['id']}: {r['score']} vs {exp} {'ok' if good else 'FAIL'}")
    return round(100 * passed / total) if total else 0, details


def prompt_component():
    text = prompt_block().lower()
    details, earned = [], 0
    for name, weight, tokens in RUBRIC:
        missing = [t for t in tokens if t.lower() not in text]
        if missing:
            details.append(f"[ ] {name} (-{weight}) missing: {', '.join(missing)}")
        else:
            earned += weight
            details.append(f"[x] {name} (+{weight})")
    score = round(100 * earned / MAX_PROMPT)
    return score, earned, details


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-history", action="store_true")
    args = ap.parse_args(argv)

    fx, fx_d = fixture_component()
    fn, fn_d = functional_component()
    pr, pr_earned, pr_d = prompt_component()

    total = round(WEIGHTS["fixture"] * fx + WEIGHTS["functional"] * fn + WEIGHTS["prompt"] * pr)

    if args.json:
        print(json.dumps({
            "total": total,
            "fixture": fx, "functional": fn, "prompt": pr,
            "prompt_points": f"{pr_earned}/{MAX_PROMPT}",
            "prompt_gaps": [d for d in pr_d if d.startswith("[ ]")],
        }, indent=2))
    else:
        print("=" * 72)
        print("chain-screener scorecard")
        print("=" * 72)
        print(f"fixture     : {fx:>3}/100  (weight {WEIGHTS['fixture']})")
        for d in fx_d:
            print(f"    {d}")
        print(f"functional  : {fn:>3}/100  (weight {WEIGHTS['functional']})")
        for d in fn_d:
            print(f"    {d}")
        print(f"prompt      : {pr:>3}/100  (weight {WEIGHTS['prompt']})  {pr_earned}/{MAX_PROMPT} pts")
        for d in pr_d:
            print(f"    {d}")
        print("-" * 72)
        print(f"TOTAL SCORE : {total}/100")
        gaps = [d.split("missing: ")[-1] for d in pr_d if d.startswith("[ ]")]
        if gaps:
            print("hill-climb next: " + " | ".join(gaps))
        else:
            print("hill-climb next: prompt rubric saturated")

    if not args.no_history:
        HISTORY.parent.mkdir(exist_ok=True)
        with HISTORY.open("a") as fh:
            fh.write(json.dumps({
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "total": total, "fixture": fx, "functional": fn, "prompt": pr,
            }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
