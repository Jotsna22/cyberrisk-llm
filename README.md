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
| LLM extractors (`GeminiExtractor`, `LLMExtractor`) | Implemented and tested with stub transports/clients. The Gemini run needs a key and network access to the Gemini API, so it is not included in the committed results. |
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
```

Run the full evaluation (4 templates × 20 seeds = 80 environments, about 2 seconds):

```bash
cyberrisk evaluate --seeds 20 --out results
# or: python scripts/run_evaluation.py --seeds 20
```

Run the LLM condition with Gemini (requires `GEMINI_API_KEY`; responses are cached under `results/llm_cache/`):

```bash
export GEMINI_API_KEY=...   # never commit this value
cyberrisk evaluate --seeds 20 --llm gemini
```

The model defaults to `gemini-2.5-flash` and can be changed with `CYBERRISK_GEMINI_MODEL`. An Anthropic-backed `LLMExtractor` is also included (requires `ANTHROPIC_API_KEY` and the `llm` extra).

## Tests

```bash
pytest -q
```

The suite has 22 tests covering the risk math, the extractors (including the stub-client LLM path), defense planning and budgets, deterministic generation, metrics, and the CLI.

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
| `graph + LLM extraction` | not run | Run with `--llm gemini` (see Usage) |

Extraction quality for the rule-based extractor: asset F1 0.822, exposure F1 0.329, vulnerability F1 0.493, link F1 0.514. The rule-based extractor recognizes only the canonical phrasing, and about two thirds of facts are paraphrased in the test text, so recall is low by design.

Model-level robustness (perturbing the planner's input model):

| Variant | Risk reduction | Controls |
|---|---|---|
| clean | 0.997 | 2.05 |
| 25% of links/vulns missing | 0.326 | 0.93 |
| 50% of links/vulns missing | 0.029 | 0.14 |
| two invented links + one invented vuln | 0.992 | 2.46 |
| critical assets relabeled low (adversarial) | 0.000 | 0 |

Full tables: `results/summary.json`, `results/per_environment.csv`, `results/model_robustness.csv`.

## Limitations

* The LLM path, which is the central research claim, is **not evaluated** in the committed results. Run `cyberrisk evaluate --llm gemini` to add it.
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
