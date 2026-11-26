# CyberRisk-LLM

LLM-assisted attack path risk assessment and adaptive defense, built as a CSCE 703 course project.

The pipeline separates **language understanding** (turning analyst text into a structured model) from **deterministic security calculation** (attack graph, risk scoring, and defense planning), so that each stage can be tested on its own.

```
text reports ──► extraction ──► Environment model ──► attack graph ──► risk engine ──► defense plan ──► simulation
 (CVE, asset,     (LLM or rules)   (assets, links,      (Internet →       (probability ×     (greedy under       (re-score on
  firewall text)                   vulns)               critical assets)   criticality × CVSS) budget)            ground truth)
```

## Status

| Component | Status |
|---|---|
| Data model, attack graph, path enumeration, risk engine | Implemented and tested |
| Greedy defense planner, CVSS-only and rule-based baselines | Implemented and tested |
| Synthetic environments (4 topologies) and report generator | Implemented and tested |
| Rule-based extractor (no LLM) | Implemented and tested |
| LLM extractors (`GeminiExtractor`, `LLMExtractor`) | Implemented and tested with stub transports/clients. The committed results include a live Gemini run (`gemini-3.5-flash-lite`, the default model). Every response is cached under `results/llm_cache/`, so the LLM results reproduce offline without an API key. `LLMExtractor` (Anthropic) has not been run live. |
| Planner-input sanity checks (`model_warnings`) | Implemented and tested. They flag degenerate extracted models (no entry point, no critical asset, dangling links) instead of letting the planner fail silently. |
| Evaluation harness, robustness experiments | Implemented; results in `results/` |
| NVD / MITRE ATT&CK ingestion | **Not implemented.** All CVE IDs are synthetic (`SYN-CVE-xxxx`). |

All assets, CVE identifiers, and scores are fictional. The synthetic CVE IDs deliberately do not match real NVD entries.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"          # core + pytest
pip install -e ".[llm]"           # optional: anthropic SDK for LLMExtractor
```

## Usage

Run the pipeline on one synthetic environment. By default the plan is made on the ground-truth model:

```bash
cyberrisk demo --template hpc --seed 3
cyberrisk demo --template hpc --seed 3 --extractor rules   # plan on rule-based extraction of the report text
cyberrisk demo --template hpc --seed 3 --extractor gemini   # plan on Gemini extraction; served from results/llm_cache/, no key needed
```

Run the full evaluation (4 templates × 20 seeds = 80 environments, about 2 seconds):

```bash
cyberrisk evaluate --seeds 20 --out results
# or: python scripts/run_evaluation.py --seeds 20
```

Run the LLM condition with Gemini. With the committed cache this reproduces the reported numbers offline, with no key and no API calls. It also writes `results/llm_robustness.csv` (4 templates × 5 seeds, `--llm-robustness-seeds`):

```bash
cyberrisk evaluate --seeds 20 --llm gemini
```

A key is needed only for reports that are not in the cache, for example with a different model or more seeds:

```bash
export GEMINI_API_KEY=...   # never commit this value
CYBERRISK_GEMINI_MODEL=gemini-3.8-flash cyberrisk evaluate --seeds 20 --llm gemini
```

The model defaults to `gemini-3.5-flash-lite`, the model the cache was built with. Cache keys include the model name. An Anthropic-backed `LLMExtractor` is also included (requires `ANTHROPIC_API_KEY` and the `llm` extra).

## Tests

```bash
pytest -q
```

The suite has 37 tests. They cover the risk math, the extractors (including the stub-client LLM path and malformed model output), defense planning and budgets, the budget sweep, planner-input warnings, deterministic generation, metrics, the CLI, and offline reproduction from the committed cache.

## Method in brief

* **Attack graph.** Nodes are assets plus an `Internet` node. An edge `u → v` exists if the firewall permits `u → v` and `v` has a vulnerability. Its probability is the best `exploitability` among `v`'s vulnerabilities, where exploitability = attack-vector factor × privilege factor.
* **Risk.** A path's probability is the product of its edge probabilities. Its risk is probability × target criticality × target CVSS impact. Total risk is the sum, over critical assets, of the worst path risk reaching each one.
* **Defense.** Two control types: `patch` (cost 1) and `block` link (cost 2). The planner is greedy by risk reduction per unit cost under a budget (default 4). Plans are chosen on the model and then simulated on the ground-truth environment.
* **Baselines.** `cvss_only` patches the highest-CVSS vulnerabilities first. `rule_based` patches exposed-asset vulnerabilities with CVSS ≥ 7 first, then the rest by CVSS. Both use the scanner list and inventory, but ignore topology.

## Results (80 synthetic environments, budget 4)

Risk reduction is measured on the ground-truth environment, so extraction errors show up as wasted or missing controls.

| Configuration | Risk reduction (mean ± sd) | Notes |
|---|---|---|
| `cvss_only` | 0.759 ± 0.291 | No topology |
| `rule_based` | 0.891 ± 0.186 | No topology; uses exposure flags |
| `graph_rule_extraction` | 0.000 ± 0.000 | Extracted graph has no attack path (see below) |
| `graph_oracle_upper_bound` | 0.997 ± 0.017 | Planner on perfect model (upper bound) |
| `graph_llm_extraction` (Gemini) | 0.997 ± 0.017 | `gemini-3.5-flash-lite`, matches the oracle |

Extraction quality:

| Extractor | Asset F1 | Exposure F1 | Vuln F1 | Link F1 | Criticality acc. | Vuln attribute acc. | Models flagged by sanity checks |
|---|---|---|---|---|---|---|---|
| Rule-based | 0.822 | 0.329 | 0.493 | 0.514 | 0.610 | 1.000 | 80 / 80 |
| Gemini | 1.000 | 1.000 | 0.9995 | 0.998 | 1.000 | 1.000 | 0 / 80 |

The rule-based extractor recognizes only the canonical phrasing, and about two thirds of facts are paraphrased in the test text, so recall is low by design. Its graph result of 0.000 comes from that: it misses most exposure lines, so the extracted graph has no entry point. The sanity checks flag all 80 of these models. *Attribute accuracy* scores the values on facts both models share (criticality; CVSS, attack vector and privilege). Set F1 cannot see a criticality downgrade, and attribute accuracy can.

Budget sweep (`results/budget_sweep.csv`). The gap between topology-aware planning and the baselines is widest when the budget is tight:

| Budget | `cvss_only` | `rule_based` | graph planner (oracle model) |
|---|---|---|---|
| 1 | 0.274 | 0.309 | 0.777 |
| 2 | 0.483 | 0.685 | 0.953 |
| 3 | 0.620 | 0.820 | 0.989 |
| 4 | 0.759 | 0.891 | 0.997 |

Model-level robustness (perturbing the planner's input model):

| Variant | Risk reduction | Controls |
|---|---|---|
| clean | 0.997 | 2.05 |
| 25% of links/vulns missing | 0.326 | 0.93 |
| 50% of links/vulns missing | 0.029 | 0.14 |
| two invented links + one invented vuln | 0.992 | 2.46 |
| critical assets relabeled low (adversarial) | 0.000 | 0 |

The sanity checks flag every adversarial model (80 / 80) and no clean model, so this failure is detected even though the planner cannot recover from it.

LLM text-level robustness (4 templates × 5 seeds, `results/llm_robustness.csv`):

| Report variant | Vuln F1 | Link F1 | Asset F1 | Risk reduction |
|---|---|---|---|---|
| clean | 0.998 | 1.000 | 1.000 | 1.000 |
| 30% of structural lines removed | 0.830 | 0.815 | 1.000 | 0.180 |
| three invented lines appended | 0.965 | 0.933 | 0.911 | 0.999 |
| appended injection line | 0.996 | 1.000 | 1.000 | 1.000 |

Full tables: `results/summary.json`, `results/per_environment.csv`, `results/model_robustness.csv`, `results/budget_sweep.csv`, `results/llm_robustness.csv`.

## Limitations

* The LLM path, which is the central research claim, is evaluated with one model (`gemini-3.5-flash-lite`), one run, on templated synthetic reports. Each fact type has only three phrasings, so a regex set covering all twelve would also score near-perfect. The LLM result shows the model reads this format. It does not yet show an advantage over a well-written parser on real, free-form analyst text.
* All data is synthetic, and the risk model is a simplified, hand-designed scoring model. The ground truth uses the same scoring model, so ranking accuracy shows pipeline fidelity, not real-world validity.
* The `cvss_only` and `rule_based` baselines use the true vulnerability list and exposure flags (a scanner plus inventory). This is a favorable assumption for them.
* The attack graph ignores privilege escalation across hops and lateral movement chains beyond `MAX_PATH_EDGES = 4`.
* `results_superseded/` contains an earlier run with sparser environments and budget 6. It is kept for transparency and is not a reported result.

## Repository layout

```
src/cyberrisk/   models.py  graph.py  defense.py  baselines.py  synthetic.py
                 extraction.py  metrics.py  experiments.py  cli.py
tests/           unit tests (pytest)
scripts/         run_evaluation.py
results/         generated CSV/JSON evaluation outputs
results_superseded/   earlier run, kept for transparency
report/          final project report (LaTeX)
```

## Team

Srija Pentyala, Siva Sai Deepank Manoj, Ubaid Khan Mohammed, Shivani Suresh, Lakshmi Jotsna Madhavarapu, Vyshnavi Pamidi
