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
fund-flow tracing service for compliance use. Read-only: never sign, never spend,
never touch private keys.

WHO IT IS FOR
A bank or payment firm that holds customer crypto in an OMNIBUS (commingled) custody
wallet: one pooled on-chain address for many customers. Per-customer attribution is
lost, so reason about POOL-LEVEL exposure and never pretend to name a customer from
chain data alone.

GOAL
Given a wallet address (or tx hash), return:
  (a) sanctions status against OFAC SDN + OpenSanctions,
  (b) entity attribution from a local label store,
  (c) an exposure report: source-of-funds and destination-of-funds as value-weighted
      breakdowns by category (SANCTIONED, MIXER, RANSOMWARE, DARKNET_MARKET, STOLEN_FUNDS,
      SCAM, EXCHANGE, ...), each with the SHARE of flow, hop distance, and direct vs
      indirect split,
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
  - fixtures/known-tainted.json (this repo): curated seeds from public incident reporting (detailed graphs).
  - fixtures/incidents.json (this repo): 12 hack incidents, each address tagged with an evidence level
    (ofac_sdn / doj_verified / fbi_published / on_chain_verified / industry_attribution / explorer_label)
    and provenance URLs. Resolve any `partial: true` (truncated) address from the cited report.
  - fixtures/known-labels.json (this repo): disclosed exchange/player wallets + known contracts, each
    with a source and a high/medium/low confidence. NOT exhaustive.
  - Scale-out label aggregators (prefer these over hand-curation): dawsbot/eth-labels (169k+ ETH labels),
    ImMike/crypto-wallet-address-labels (incl. Elliptic BTC dataset), Blockscout label API,
    OFAC-sanctioned-address list (0xB10C), OpenSanctions.

ADDRESS NORMALIZATION (per chain)
  - EVM: lowercase hex, validate EIP-55, strip 0x for storage, re-add on output.
  - Bitcoin: detect and tag script type (P2PKH legacy, P2SH nested segwit, P2WPKH bech32,
    P2WSH, taproot). Never case-fold bech32 before validating the checksum.
  - Store (chain, normalized_addr) as the unique key. Same hex on ETH and ARB is NOT the same
    address context — tag by chain.

SANCTIONS MATCHER
  - Exact match on (chain, normalized_addr) against the ingested lists.
  - Output: list_name, entity_name, program, listing_date, source_url, confidence.

EXPOSURE / TRACE ENGINE
  - Model the chain as a directed transfer graph: nodes = addresses, edges =
    {tx_hash, from, to, asset, amount, block, chain, hop}.
  - Ethereum + Arbitrum: build edges from eth_getLogs (ERC-20 Transfer) + native value
    transfers (receipts). NOTE: most free public RPCs do NOT expose trace_* /
    debug_traceTransaction, so internal/native transfers embedded in contract calls may be
    invisible. Document this gap explicitly in limits.known_gaps; do not silently undercount.
  - Bitcoin: walk UTXOs from your own node via getrawtransaction (txindex=1) / gettxout.
    Follow outputs; support forward (spend) and backward (funding) traversal.
  - SANCTIONS HOP COMPLETENESS: for the SANCTIONED category only, keep tracing through all
    hops until exposure to a sanctioned actor is detected or the component is exhausted. Do
    not stop at a fixed hop budget - a fixed cap (3 or 5 hops) is a known compliance failure
    that Lazarus-style multi-hop layering defeats. Use the hop cap only to bound non-sanctions
    heuristic scoring and runtime, never to declare a sanctions "clear".

TAINT PROPAGATION
  - BFS from each seed. Each hop decays the taint weight (default decay=0.5/hop, configurable).
  - Record the shortest path and the min-hop distance from any seed.
  - Handle cycles and high-fan-out nodes with a visited set and a visit cap.
  - LABEL DAMPENING: when the counterparty is a known service/exchange cluster, DAMPEN the
    score. Exchange hot wallets carry indirect-exposure flags from commingled funds - their
    label is a strong dampener, not an accusation. An exchange-labeled wallet at score 60 is
    structurally different from an unlabeled wallet at score 60.

BRIDGE / CROSS-CHAIN
  - If a tainted ETH address sends into the Arbitrum canonical bridge
    (L1 Inbox / L1StandardBridge deposit, L2 withdrawal), match the L1 deposit to the L2
    withdrawal using the bridge's sequence number where possible, and continue the trace on the
    destination chain. Flag the leg as "cross-chain hop".

SCORING (0-100)
  - score = max of matched label scores, blended with the value-weighted indirect exposure;
    then apply label dampening for known service/exchange clusters.
  - 100: direct exact sanctions hit OR direct seed hit.
  - 80-99: <= 1 hop from a seed, or attribution to a known-bad cluster.
  - 50-79: 2-3 hops, material amount.
  - 20-49: >= 4 hops or dust-only connection.
  - 0-19: no path to any seed within the hop cap.
  - Always return the evidence list (paths, amounts, value-weighted shares, distances) that
    yielded the score.

OMNIBUS / BANK COMPLIANCE
  - The target user is a bank custodying customer funds in a commingled/omnibus wallet. Screen
    the omnibus wallet itself AND every counterparty on deposit - not just the wallet.
  - A tainted inflow is whole-pool exposure until the specific depositor is identified from the
    bank's own ledger; never attribute a customer from chain data.
  - On a direct sanctions hit (score >= 90): produce an escalation recommendation (reject/freeze
    before crediting, preserve evidence) and support filing a SAR (suspicious activity report).
  - Outbound transfers to a designated address are their own violation - flag them.
  - DUST RULE: amount may lower risk but must never erase a designated-source hit.
  - Travel Rule context: support screening of senders, recipients and counterparties, including
    unhosted (self-custody) wallets, per FATF Recommendation 16.

NEGATIVE CONTROLS
  - Avoid false positives: a known-clean exchange wallet or a fresh benign address must score
    < 20 (LOW) with zero sanctions entries. Ship explicit control cases.

AUDIT & RECORDS
  - Emit an immutable audit record per screen: the input, the result, the list version / snapshot
    used, and the time the address was screened at. The response is the record.
  - Support re-screen of a customer book when a sanctions list refresh lands, and re-score
    affected wallets retroactively.

OUTPUT (JSON, stable key order)
  { "input", "chain", "sanctions": [...], "attribution": [...],
    "exposure": { "source_of_funds": [...], "destination_of_funds": [...] },
    "risk_score", "risk_band", "paths": [...], "truncated": bool,
    "limits": { "max_hops", "decay", "rpc", "known_gaps": [...] },
    "audit": { "screened_at", "list_versions": {...} } }
  Also emit a Mermaid + Graphviz view of the traced subgraph for humans.

RESILIENCE
  - All external calls: timeout, retry with backoff, and cache to sqlite (never re-fetch a
    block/range you already have). Assume public RPCs rate-limit and sometimes lie; verify
    block continuity.
  - Degrade gracefully: if trace methods are unavailable, say so in "limits.known_gaps"
    rather than returning a wrong answer.
  - Fail-closed for sanctions gating: if the sanctions data or the indexer is unavailable, do
    NOT silently return "clean".

DEFINITION OF DONE
  - Passes every eval in Section 3 (fixtures in fixtures/).
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

Fixtures live in `fixtures/known-tainted.json` (detailed graphs), `fixtures/incidents.json`
(12 incidents, evidence-tagged) and `fixtures/known-labels.json` (exchange/entity labels).

- **Real-world seeds** — addresses published in government/industry incident reporting.
- **Synthetic graphs** — deterministic constructed graphs with hand-computed expected taint.
- **Negative controls** — known-clean addresses (e.g. ETH2 deposit contract, exchange hot wallets) that must NOT flag.

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

## 4. Compliance context: banks & omnibus wallets

This is written for a **bank or payment firm that holds customer crypto in an omnibus
(commingled) wallet** — one pooled on-chain address that custodies funds for many customers at
once. Exchange hot wallets are the canonical real-world example; the same shape applies to a
bank's pooled custody address.

### The omnibus problem

When funds for thousands of customers sit in one address, **per-customer attribution is gone**.
You can see everything that enters and leaves the pool, but not *whose* money it is. Two
consequences drive everything here:

1. **A tainted deposit taints the pool.** One sanctioned or hack-linked inflow is exposure for
   the whole commingled balance, not just the one customer — under strict-liability sanctions
   regimes the size of the deposit is irrelevant.
2. **You cannot "just remove" the bad customer.** The pool is fungible; the responsible
   depositor can only be named from *your own off-chain deposit records*, never from chain data.

### What screening answers — and what it cannot

| Question | Answerable from open data? |
|---|---|
| Is *this wallet* on a sanctions list? | **Yes** — exact match on OFAC SDN / OpenSanctions. |
| Who owns this wallet (exchange, bridge, cluster)? | **Yes, probabilistically** — public labels. |
| Does the pool have inbound/outbound exposure to tainted funds? | **Yes** — graph trace to nearest seed, with hop distance. |
| How far (hops) is the exposure? Does it cross a bridge? | **Yes** — taint BFS + cross-chain leg matching. |
| *Which customer* deposited the tainted funds? | **No** — needs the bank's own deposit ledger. |
| Is the custodian solvent / honest? | **No** — taint scoring is blind to custody risk (see the FTX scenario). |
| Internal/native transfers hidden inside contract calls? | **Often no** on free RPCs — documented in `limits.known_gaps`. |

### Regulatory frame (plain language, not legal advice)

- **OFAC / sanctions:** strict liability in the US — a designated counterparty in the pool is a
  problem regardless of intent or amount. Outbound transfers *to* a designated address are their
  own violation.
- **FATF Recommendation 16 (Travel Rule):** originator/beneficiary information must travel with
  transfers; omnibus pooling makes satisfying this depend on your internal ledger.
- **BSA / AML:** suspicious activity triggers a SAR; sanctions hits may require blocking reports.
- **EU AMLR / MiCA** and similar regimes add transfer-of-funds and custody rules.

### Worked scenarios (`fixtures/omnibus-cases.json`)

Six bank-facing scenarios, each with an expected score, over real labeled wallets + real
seeds (constructed flows are flagged `scenario: true`): direct sanctioned inflow, two-hop
Lazarus taint, one-tainted-depositor-in-a-clean-pool, outbound to a sanctioned mixer, an
untraceable custody failure, and a clean negative control. Run them:

```bash
python3 demo/omnibus_screen.py          # full compliance report + pass/fail
python3 demo/omnibus_screen.py --wallet 0xf977814e90da44bfa03b6295a0616a897441acec
python3 demo/omnibus_screen.py --json
```

The demo is **offline and deterministic** (stdlib only): it replays the fixture graph, so it
runs with no RPC and no node.

### Minimum control set a bank should wrap around this

1. Screen the omnibus wallet **and every counterparty on deposit** — not just the wallet.
2. On a direct sanctions hit (score ≥ 90): **escalate, evaluate reject/freeze before crediting,
   and file where warranted** — do not net or net-off.
3. Treat a tainted inflow as **whole-pool exposure** until the depositor is identified from your
   ledger.
4. **Never dismiss a designated source on amount.** A dust rule may lower risk; it does not
   erase designated-source exposure.
5. **Document the known gaps** (no internal-transfer tracing on free RPCs; no off-chain legs) in
   every report you rely on.
6. **Re-screen continuously,** not only at onboarding.

> Not legal or compliance advice. This is an engineering demonstration of what open data can and
> cannot support; a real program needs counsel, a licensed analytics vendor where required, and
> your own transaction-monitoring controls.

## 5. Incident cases (`fixtures/incidents.json`)

12 cases, each seeded with at least one address and an evidence level. Two (Bybit, Coldcard) also
appear in `known-tainted.json` with fuller graphs. Addresses marked `partial` were published
truncated and must be resolved from the cited report before use.

| # | ID | Date | Chain | Loss | Actor | Evidence |
|---|---|---|---|---|---|---|
| 1 | `bitfinex_2016` | 2016-08-02 | BTC | 119,754 BTC | Lichtenstein / Razzlekhan (convicted) | DOJ |
| 2 | `kucoin_2020` | 2020-09-26 | ETH | ~$281M | unattributed | explorer label |
| 3 | `poly_network_2021` | 2021-08-10 | ETH/BSC/Polygon | ~$611M | "Mr. White Hat" (returned) | on-chain |
| 4 | `wormhole_2022` | 2022-02-02 | ETH/SOL | 120k wETH (~$326M) | unattributed | industry |
| 5 | `ronin_2022` | 2022-03-23 | ETH | ~$625M | Lazarus / DPRK | **OFAC SDN** |
| 6 | `harmony_horizon_2022` | 2022-06-23 | ETH/BSC | ~$100M | unattributed (Lazarus?) | industry |
| 7 | `nomad_2022` | 2022-08-01 | ETH | ~$190M | bitliq.eth + copycats | industry |
| 8 | `bnb_bridge_2022` | 2022-10-06 | BSC/ETH | 2M BNB (~$570M) | unattributed | industry |
| 9 | `ftx_2022` | 2022-11-11 | ETH | ~$600M | unattributed | explorer label |
| 10 | `euler_2023` | 2023-03-13 | ETH | ~$197M | "Jacob" (returned) | industry |
| 11 | `bybit_2025` | 2025-02-21 | ETH/ARB | ~$1.5B | Lazarus / DPRK | on-chain + **FBI** |
| 12 | `coldcard_2026` | 2026-07-30 | BTC | ≥1,778 BTC | ≥15 clusters | industry |

**Why these:** the set spans attribution types (government-sanctioned, DOJ-convicted, explorer-labeled,
industry-attributed), chains (ETH, BSC, Polygon, Arbitrum, Solana, Bitcoin), and topologies (single
exploiter, multi-address syndicate, and Coldcard's many-to-few fan-in). That diversity is what makes
the evals meaningful rather than one-happy-path.

## 6. Known entity labels (`fixtures/known-labels.json`)

Disclosed exchange/player wallets + known contracts. Each row carries `source` and `confidence`:

- **high** — official exchange disclosure or Etherscan-verified name tag.
- **medium** — leading label aggregator (Blockscout / Etherscan label cloud). Verify before relying.
- **low** — single community source.

Coverage in the file: **Binance, Coinbase, KuCoin, OKX, Kraken, Gemini, Bybit, Bitget, Bitfinex,
Deribit, Coinmetro, Bitvavo, xs2.exchange** (48 wallets) plus contracts (ETH2 deposit, Tornado Cash
Router + 0.1 ETH pool [OFAC], Wormhole bridge, Nomad replica).

Key principle: **use the aggregators as the scalable source of truth, keep curated fixtures as
deterministic test data.** The curated list is a seed, not the product. Live sources:

| Source | What | Scale |
|---|---|---|
| [dawsbot/eth-labels](https://github.com/dawsbot/eth-labels) | Aggregated ETH labels (exchanges, DEX, bridges, MEV, etc.) | 169k+ |
| [ImMike/crypto-wallet-address-labels](https://github.com/ImMike/crypto-wallet-address-labels) | Curated CSVs + Elliptic BTC dataset | ~46k labeled |
| [0xB10C/ofac-sanctioned-addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) | Nightly OFAC SDN per-asset address lists | official |
| [OpenSanctions](https://www.opensanctions.org/datasets/) | Consolidated sanctions/PEP + crypto entities | official |
| [KuCoin PoR](https://www.kucoin.com/proof-of-reserves) | Exchange-published own wallets | official |

---

## 7. Prior art / honest limitation

The tracing tech here is **commoditized**; the moat that Elliptic/Chainalysis sell is a
**proprietary label database** (millions of addresses from clustering + exchange partnerships).
That is not reproducible from free sources. This project targets the reproducible part:
sanctions screening, public attribution, and honest, evidence-backed taint with documented gaps.

### References

- 12 historical incidents with evidence levels + provenance URLs — see `fixtures/incidents.json`.
- Exchange/entity labels with source + confidence — see `fixtures/known-labels.json`.
- Bybit/Lazarus 2025 — incident addresses & FBI attribution (see `fixtures/known-tainted.json`).
- Coldcard RNG entropy flaw, July 2026 — Galaxy Research flow-of-funds mapping; Coinkite advisory.
- OFAC SDN list — treasury.gov sanctions list service; nightly mirror: 0xB10C/ofac-sanctioned-digital-currency-addresses.
- OpenSanctions — consolidated sanctions + crypto datasets.
- dawsbot/eth-labels & ImMike/crypto-wallet-address-labels — public label aggregators.
- GLEIF — LEI legal-entity registry (entity metadata only; no wallet mapping).
- Meiklejohn et al., *A Fistful of Bitcoins* — UTXO clustering heuristics.
