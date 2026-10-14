# chain-screener

Open-source wallet screening + fund-flow tracing: sanctions checks, entity attribution, and
multi-hop trace from chain data. Spiritual cousin of Elliptic/Chainalysis, built from free and
authoritative sources only.

Chains: **Ethereum**, **Arbitrum One**, **Bitcoin**.

> **Scope honesty first.** This does **not** produce KYC. Real KYC (name/DOB/ID of a wallet owner)
> lives inside exchanges and is never public. What open data gives you is:
> 1. **Sanctions status** — is this address on OFAC SDN / EU / UK / UN lists?
> 2. **Attribution** — which known entity owns this address (exchange, bridge, hacker cluster)?
> 3. **Taint / fund-flow** — how funds moved across hops, and how close a wallet is to a known-tainted origin.
>
> Anything sold as "KYC of a wallet" from open sources is attribution rebranded. Say attribution.

---

## 1. The Prompt

Copy-paste this into a coding agent (Claude Code / Codex / opencode) to build the MVP.

```text
ROLE
You are a senior blockchain-data engineer. Build a read-only wallet screening and
fund-flow tracing service. Read-only: never sign, never spend, never touch private keys.

GOAL
Given a wallet address (or tx hash), return:
  (a) sanctions status against OFAC SDN + OpenSanctions,
  (b) entity attribution from a local label store,
  (c) a taint report: fund-flow paths up to K hops from the nearest known-tainted seed,
  (d) a 0-100 risk score with the evidence that produced it.

CHAINS
  - Ethereum mainnet (chainId 1)
  - Arbitrum One (chainId 42161)
  - Bitcoin mainnet (your own bitcoind, txindex=1)

HARD CONSTRAINTS
  - Python 3.11+, STDLIB ONLY (no pip, no web3.py, no requests). Use urllib, json, sqlite3,
    argparse, dataclasses. If a dependency seems necessary, stop and justify it in the PR.
  - Read-only RPC. Public/free endpoints only. No API keys committed. No paid providers.
  - Never log or emit secrets. No server-side file access.
  - Deterministic output: same inputs -> byte-identical JSON.

DATA SOURCES (free, authoritative)
  - OFAC SDN: SDN list XML/CSV from treasury.gov; extract entries whose <idType> is
    "Digital Currency Address - XBT/ETH/..." (address + entity + program + listing date).
  - OpenSanctions: the sanctions + crypto datasets (aggregate of OFAC/EU/UK/UN and more).
    Prefer the pre-built JSON/bulk target over scraping.
  - GLEIF: legal-entity file / API. WARNING: GLEIF maps legal entities (LEI -> name, country,
    parent). It does NOT map wallets to entities. Use it only to enrich an entity you have
    already attributed by other means. Do not pretend it screens wallets.
  - fixtures/known-tainted.json (this repo): curated seeds from public incident reporting.

ADDRESS NORMALIZATION (per chain)
  - EVM: lowercase hex, validate EIP-55, strip 0x for storage, re-add on output.
  - Bitcoin: detect and tag script type (P2PKH legacy, P2SH nested segwit, P2WPKH bech32,
    P2WSH, taproot). Never case-fold bech32 before validating the checksum.
  - Store (chain, normalized_addr) as the unique key. Same hex on ETH and ARB is NOT the same
    address context — tag by chain.

SANCTIONS MATCHER
  - Exact match on (chain, normalized_addr) against the ingested lists.
  - Output: list_name, entity_name, program, listing_date, source_url, confidence.

TIANT / TRACE ENGINE
  - Model the chain as a directed transfer graph: nodes = addresses, edges =
    {tx_hash, from, to, asset, amount, block, chain, hop}.
  - Ethereum + Arbitrum: build edges from eth_getLogs (ERC-20 Transfer) + native value
    transfers (receipts). NOTE: most free public RPCs do NOT expose trace_* /
    debug_traceTransaction, so internal/native transfers embedded in contract calls may be
    invisible. Document this gap explicitly in the report; do not silently undercount.
  - Bitcoin: walk UTXOs from your own node via getrawtransaction (txindex=1) / gettxout.
    Follow outputs; support forward (spend) and backward (funding) traversal.
  - Taint propagation: BFS from each seed. Each hop decays the taint weight
    (default decay=0.5/hop, configurable). Record the shortest path and the min-hop distance
    from any seed. Handle cycles and high-fan-out (exchange) nodes with a visited set and a
    visit cap.

BRIDGE / CROSS-CHAIN
  - If a tainted ETH address sends into the Arbitrum canonical bridge
    (L1 Inbox / L1StandardBridge deposit, L2 withdrawal), match the L1 deposit to the L2
    withdrawal using the bridge's sequence number where possible, and continue the trace on the
    destination chain. Flag the leg as "cross-chain hop".

SCORING (0-100)
  - 100: direct exact sanctions hit OR direct seed hit.
  - 80-99: <= 1 hop from a seed, or attribution to a known-bad cluster.
  - 50-79: 2-3 hops, material amount.
  - 20-49: >= 4 hops or dust-only connection.
  - 0-19: no path to any seed within K hops.
  - Always return the evidence list (paths, amounts, distances) that yielded the score.

OUTPUT (JSON, stable key order)
  { "input", "chain", "sanctions": [...], "attribution": [...],
    "risk_score", "risk_band", "paths": [...], "truncated": bool,
    "limits": { "max_hops", "decay", "rpc", "known_gaps": [...] } }
  Also emit a Mermaid + Graphviz view of the traced subgraph for humans.

RESILIENCE
  - All external calls: timeout, retry with backoff, and cache to sqlite (never re-fetch a
    block/range you already have). Assume public RPCs rate-limit and sometimes lie; verify
    block continuity.
  - Degrade gracefully: if trace methods are unavailable, say so in "limits.known_gaps"
    rather than returning a wrong answer.

DEFINITION OF DONE
  - Passes every eval in Section 3 (fixtures in fixtures/known-tainted.json).
  - `python -m chain_screener.cli screen --chain eth --addr <A>` runs offline against a
    pre-fetched sqlite cache.
  - `python -m chain_screener.evals` prints a PASS/FAIL table.
  - No non-stdlib imports. No committed secrets.
```

---

## 2. The Plan

### Architecture

```
 ingest -> normalize -> store -> screen -> trace -> score -> report
```

| Stage | Responsibility |
|---|---|
| **ingest** | Pull OFAC SDN, OpenSanctions, GLEIF entity file; load local fixtures; cache raw. |
| **normalize** | Per-chain address canonicalization + script-type / EIP-55 validation. |
| **store** | SQLite: `sanctions`, `labels`, `edges`, `nodes`, `cache_blocks`, `provenance`. |
| **screen** | Exact sanctions + attribution lookup for a single address. |
| **trace** | Build/consume the transfer graph; BFS taint from seeds with hop decay. |
| **score** | Risk 0-100 + evidence bundle. |
| **report** | JSON (machine) + Mermaid/DOT (human) + optional HTML. |

### Chain adapters (read-only)

| Chain | Transport | Tracing method | Free-node caveat |
|---|---|---|---|
| Ethereum | JSON-RPC (publicnode / cloudflare) | `eth_getBlockByNumber`, `eth_getLogs` (ERC-20), receipts for native value | no `trace_*` — internal transfers invisible |
| Arbitrum One | JSON-RPC (`arb1.arbitrum.io/rpc`) | same as Ethereum + L2 receipt fields (`l1BlockNumber`) | same trace gap; bridge matching via sequence numbers |
| Bitcoin | own `bitcoind` RPC | `getrawtransaction`/`gettxout` UTXO walk (requires `txindex=1`) | needs a synced node + disk |

### Phases

**P0 — Scaffold + ingest**
Deliverable: `chain_screener/{ingest,store}`; OFAC + OpenSanctions parsed into `sanctions`;
GLEIF entity file into `labels` (entity metadata only). Verification: row counts, 3 known
sanctioned addresses resolve to their entity.

**P1 — Normalize + screen**
Deliverable: address normalization (EVM + BTC), `screen` command. Verification: eval E1/E5.

**P2 — Chain adapters**
Deliverable: ETH + ARB transfer graph builder over a cached block range; BTC UTXO walker.
Verification: reconstruct a known Bybit drain edge; walk a known BTC funding path.

**P3 — Taint engine**
Deliverable: BFS taint with decay, cycle handling, fan-out cap, path reconstruction.
Verification: eval E2/E3/E4.

**P4 — Scoring + reports**
Deliverable: risk score + evidence + Mermaid/DOT. Verification: eval E6 (determinism) +
report renders.

**P5 — Evals + CI**
Deliverable: `python -m chain_screener.evals`, GitHub Action running on push.
Verification: green CI, no non-stdlib imports (CI greps imports).

### Out of scope (v1)
Real KYC. Writing/signing. Paid trace nodes. Full historical backfill of every chain.
ML clustering. Real-time alerting. These are later; see "Honest limitation" below.

---

## 3. Evals

Fixtures live in `fixtures/known-tainted.json`. Two kinds:

- **Real-world seeds** — addresses published in government/industry incident reporting.
- **Synthetic graphs** — deterministic constructed graphs with hand-computed expected taint.

### Eval matrix

| ID | Name | Fixture | Pass condition |
|---|---|---|---|
| **E1** | Sanctions exact match | `bybit_2025.exploiters` | `screen(eth, 0x47666Fab…486E2)` → `risk_score=100`, band `CRITICAL`, ≥1 sanctions/attribution entry naming Bybit Exploiter / Lazarus (DPRK). |
| **E2** | Forward taint reach | Bybit ETH drain tx | Trace forward ≤3 hops from the drain tx → reaches ≥1 FBI-attributed address (`0x51E9…` / `0x9624…` / `0x83c7…`); path printed with amounts. |
| **E3** | Bitcoin fan-in clustering | `coldcard_2026` | Given the victim set, engine identifies the 4 collector addresses as a common sink (fan-in ratio ≥ threshold) and flags the cluster; resolves the published collector prefixes to full addresses from the Galaxy list. |
| **E4** | Cross-chain bridge hop | `bybit_2025` + Arbitrum | Tainted ETH deposited to the canonical bridge on L1 is matched to the L2 withdrawal and flagged as a `cross-chain hop`; trace continues on Arbitrum. |
| **E5** | No false positive (control) | `controls.clean` | A fresh/benign address and a known exchange hot wallet → `risk_score < 20`, band `LOW`, zero sanctions entries. |
| **E6** | Determinism | any | Running the same query twice yields byte-identical JSON (stable sort, stable key order). |

### Metrics (report on every eval run)

- **Sanctions recall** = matched / seeded-sanctioned addresses. Target **1.00** on fixtures.
- **Taint recall@K** = seeds reached within K hops / seeds reachable within K hops. Target **1.00**.
- **False-positive rate** = flagged benign / benign set. Target **0.00** on `controls.clean`.
- **Determinism** = hash equality across two runs. Target **pass**.
- **Latency** = wall-clock per `screen`/`trace` on cached data. Budget **< 2 s** cached, **< 30 s** cold (small hop cap).

### Acceptance gate

MVP is "done" when E1–E6 pass and the metric targets above are met on the fixture set, with
`limits.known_gaps` honestly reflecting the public-RPC trace limitation.

### Why these hacks

- **Bybit / Lazarus (Feb 2025)** — largest crypto theft to date (~$1.5B, 401,346 ETH). Clean
  ground truth: exploited cold wallet, malicious implementation contract, main exploiter, and an
  FBI-published address list to check taint reach. Also exercises cross-chain legs.
- **Coldcard cold-wallet exploit (Jul 2026)** — opposite topology from Bybit: thousands of
  independent victim wallets fan-in to a handful of collectors. Tests clustering + fan-in
  detection on Bitcoin, not a single exploit address.

---

## 4. Prior art / honest limitation

The tracing tech here is **commoditized**; the moat that Elliptic/Chainalysis sell is a
**proprietary label database** (millions of addresses from clustering + exchange partnerships).
That is not reproducible from free sources. This project targets the reproducible part:
sanctions screening, public attribution, and honest, evidence-backed taint with documented gaps.

### References

- Bybit/Lazarus 2025 — incident addresses & FBI attribution (see `fixtures/known-tainted.json`).
- Coldcard RNG entropy flaw, July 2026 — Galaxy Research flow-of-funds mapping; Coinkite advisory.
- OFAC SDN list — treasury.gov sanctions list service.
- OpenSanctions — consolidated sanctions + crypto datasets.
- GLEIF — LEI legal-entity registry (entity metadata only; no wallet mapping).
- Meiklejohn et al., *A Fistful of Bitcoins* — UTXO clustering heuristics.
