#!/usr/bin/env python3
"""chain-screener - offline omnibus-wallet compliance demo (Python stdlib only).

Replays the constructed scenario graph in fixtures/omnibus-cases.json against the
real seeds in fixtures/incidents.json and the labels in fixtures/known-labels.json,
then prints a bank-facing compliance report per case.

Usage:
    python3 demo/omnibus_screen.py
    python3 demo/omnibus_screen.py --json
    python3 demo/omnibus_screen.py --wallet 0xf977814e90da44bfa03b6295a0616a897441acec
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "fixtures"
DEFAULT_MAX_HOPS = 3
DUST_ETH = 0.01


def load(name):
    return json.loads((FIX / name).read_text())


def norm(addr):
    return addr.lower()


def band(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW-MEDIUM"
    return "LOW"


def build_world():
    incidents = load("incidents.json")
    labels = load("known-labels.json")
    omnibus = load("omnibus-cases.json")

    seeds = {}
    for inc in incidents["incidents"]:
        sanctioned = inc.get("evidence") == "ofac_sdn"
        for s in inc.get("seeds", []):
            if s.get("partial"):
                continue
            a = norm(s["addr"])
            seeds[a] = {
                "incident": inc["id"],
                "sanctioned": bool(s.get("sanctioned") or sanctioned),
                "role": s.get("role", ""),
            }

    for c in labels.get("known_contracts", []):
        a = norm(c["addr"])
        seeds[a] = {
            "incident": c["name"],
            "sanctioned": c.get("source") == "ofac_sdn",
            "role": c.get("role", ""),
        }

    for case in omnibus["cases"]:
        ts = case.get("tainted_source")
        if ts:
            a = norm(ts["addr"])
            existing = seeds.get(a, {})
            seeds[a] = {
                "incident": ts.get("incident", existing.get("incident", "scenario")),
                "sanctioned": bool(ts.get("sanctioned", existing.get("sanctioned", False))),
                "role": existing.get("role", "scenario source"),
            }

    attribution = {}
    for w in labels.get("exchange_wallets", []):
        label = w["label"]
        if not label.lower().startswith(w["exchange"].lower()):
            label = f"{w['exchange']}: {label}"
        attribution[norm(w["addr"])] = label

    out_edges = {}
    in_edges = {}
    for e in omnibus["graph"]:
        f, t = norm(e["from"]), norm(e["to"])
        out_edges.setdefault(f, []).append(e)
        in_edges.setdefault(t, []).append(e)
    for d in (out_edges, in_edges):
        for k in d:
            d[k].sort(key=lambda x: (x["from"], x["to"], x["amount"]))

    return seeds, attribution, omnibus, out_edges, in_edges


def bfs_inbound(start, seeds, in_edges, cap):
    if start in seeds:
        return 0, [start], start
    seen = {start}
    q = deque([(start, [start])])
    while q:
        node, path = q.popleft()
        if len(path) - 1 >= cap:
            continue
        for e in in_edges.get(node, []):
            src = norm(e["from"])
            if src in seen:
                continue
            np = path + [src]
            if src in seeds:
                return len(np) - 1, np, src
            seen.add(src)
            q.append((src, np))
    return None, None, None


def screen(addr, seeds, attribution, out_edges, in_edges, cap):
    a = norm(addr)
    self_seed = seeds.get(a)
    evidence = []

    inbound_hop, inbound_path, reached = bfs_inbound(a, seeds, in_edges, cap)

    outbound_sanctioned = [
        e for e in out_edges.get(a, [])
        if norm(e["to"]) in seeds and seeds[norm(e["to"])]["sanctioned"]
    ]

    inbound_sanctioned = bool(reached and seeds[reached]["sanctioned"])

    if self_seed and self_seed["sanctioned"]:
        score, note = 100, "wallet address is itself an OFAC-designated seed"
    elif outbound_sanctioned:
        score, note = 95, "outbound transfer to a sanctioned counterparty"
    elif inbound_hop == 1:
        score = 92 if inbound_sanctioned else 85
        note = f"direct inflow from a {'sanctioned' if inbound_sanctioned else 'hack-linked'} seed (1 hop)"
    elif inbound_hop is not None and inbound_hop <= 3:
        score, note = 65, f"tainted inflow within {inbound_hop} hops"
    elif inbound_hop is not None:
        score, note = 35, f"distant tainted inflow ({inbound_hop} hops, exceeds cap)"
    else:
        score, note = 5, f"no path to any seed within {cap} hops"

    if inbound_path and inbound_hop and inbound_hop >= 1:
        edge_amount = None
        for e in in_edges.get(a, []):
            if norm(e["from"]) == reached:
                edge_amount = e["amount"]
                break
        if edge_amount is not None and edge_amount < DUST_ETH:
            score = min(score, 45)
            note += f"; inflow {edge_amount} ETH is dust-sized, capped"

    return {
        "wallet": a,
        "attribution": attribution.get(a, "unknown / unlabeled"),
        "sanctioned_self": bool(self_seed and self_seed["sanctioned"]),
        "inbound_hop": inbound_hop,
        "inbound_path": [norm(x) for x in inbound_path] if inbound_path else [],
        "inbound_reached": reached,
        "inbound_sanctioned": inbound_sanctioned,
        "outbound_sanctioned": [norm(e["to"]) for e in outbound_sanctioned],
        "score": score,
        "band": band(score),
        "note": note,
        "evidence": evidence,
    }


def fmt_path(rev_path, in_edges):
    if not rev_path:
        return "(none)"
    fwd = list(reversed(rev_path))
    parts = []
    for i in range(len(fwd) - 1):
        src, dst = fwd[i], fwd[i + 1]
        amt = ""
        tx = ""
        for e in in_edges.get(dst, []):
            if norm(e["from"]) == src:
                amt = f" {e['amount']} {e['asset']}"
                tx = f" tx={e['tx']}"
        parts.append(f"{src} ->{amt}{tx}")
    parts.append(fwd[-1])
    return "  |  ".join(parts)


def print_case(case, seeds, attribution, out_edges, in_edges, cap):
    r = screen(case["omnibus_wallet"]["addr"], seeds, attribution, out_edges, in_edges, cap)
    exp = case["expected"]
    match = "MATCH" if r["score"] == exp["risk_score"] else "MISMATCH"

    print(f"\n### {case['id']} - {case['title']}")
    print(f"  scenario        : {case['scenario']}")
    print(f"  omnibus wallet  : {r['attribution']}  ({'0x' + r['wallet'][2:]})")
    print(f"  sanctions (self): {'SANCTIONED' if r['sanctioned_self'] else 'none'}")
    print(f"  inbound exposure: {r['inbound_hop'] if r['inbound_hop'] is not None else 'none'} hop(s)"
          + (f"  reached={r['inbound_reached']}  sanctioned={r['inbound_sanctioned']}"
             if r["inbound_reached"] else ""))
    if r["inbound_path"]:
        print(f"    path          : {fmt_path(r['inbound_path'], in_edges)}")
    if r["outbound_sanctioned"]:
        print(f"  outbound sanc.  : {', '.join(r['outbound_sanctioned'])}")
    print(f"  reasoning       : {r['note']}")
    print(f"  RISK SCORE      : {r['score']}  [{r['band']}]")
    print(f"  recommended     : {exp['action']}")
    print(f"  expected        : {exp['risk_score']} [{exp['band']}]  -> {match}")
    return r["score"] == exp["risk_score"], r


def run_all(payload, seeds, attribution, out_edges, in_edges, cap):
    results = []
    passed = 0
    print("=" * 78)
    print("chain-screener - bank omnibus-wallet compliance report (offline demo)")
    print(f"max hops = {cap} | dusty cap = {DUST_ETH} ETH | scenario graph from fixtures")
    print("=" * 78)
    for case in payload["cases"]:
        ok, r = print_case(case, seeds, attribution, out_edges, in_edges, cap)
        passed += int(ok)
        results.append({"id": case["id"], **r, "expected_score": case["expected"]["risk_score"], "match": ok})

    total = len(payload["cases"])
    score = round(100 * passed / total)
    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"{'case':38} {'score':>6} {'band':>12} {'expect':>7}  match")
    for r in results:
        print(f"{r['id']:38} {r['score']:>6} {r['band']:>12} {r['expected_score']:>7}  {'ok' if r['match'] else 'NO'}")
    print(f"\nfunctional eval score: {score}/100  ({passed}/{total} cases match expected)")
    return score, results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline omnibus-wallet compliance demo.")
    ap.add_argument("--wallet", help="screen a single address instead of all cases")
    ap.add_argument("--max-hops", type=int, default=DEFAULT_MAX_HOPS)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)

    seeds, attribution, payload, out_edges, in_edges = build_world()

    if args.wallet:
        r = screen(args.wallet, seeds, attribution, out_edges, in_edges, args.max_hops)
        if r["inbound_path"]:
            r["inbound_path_str"] = fmt_path(r["inbound_path"], in_edges)
        if args.json:
            print(json.dumps(r, indent=2, sort_keys=True))
        else:
            print(f"wallet          : {r['attribution']}  ({args.wallet})")
            print(f"sanctions (self): {'SANCTIONED' if r['sanctioned_self'] else 'none'}")
            print(f"inbound hop     : {r['inbound_hop']}")
            print(f"outbound sanc.  : {r['outbound_sanctioned']}")
            print(f"RISK SCORE      : {r['score']} [{r['band']}]")
            print(f"reasoning       : {r['note']}")
        return 0

    score, results = run_all(payload, seeds, attribution, out_edges, in_edges, args.max_hops)
    if args.json:
        print(json.dumps({"score": score, "results": results}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
