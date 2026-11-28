# CyberRisk-LLM

LLM-assisted attack path risk assessment and adaptive defense, built as a CSCE 703 course project.

The pipeline separates **language understanding** (turning analyst text into a structured model) from **deterministic security calculation** (attack graph, risk scoring, and defense planning), so that each stage can be tested on its own.

```
text reports ──► extraction ──► Environment model ──► attack graph ──► risk engine ──► defense plan ──► simulation
 (CVE, asset,     (LLM or rules)   (assets, links,      (Internet →       (probability ×     (greedy under       (attacker simulation
  firewall text)                   vulns)               critical assets)   criticality × CVSS) budget)            on ground truth)
```

## Status

| Component | Status |
|---|---|
| Data model, attack graph, path enumeration, risk engine | Implemented and tested |
| Greedy defense planner, CVSS-only and rule-based baselines | Implemented and tested |
| Synthetic environments (4 topologies) and report generator | Implemented and tested |
| Rule-based extractor (no LLM) | Implemented and tested |
| Template parser (`TemplateExtractor`, no LLM) | Implemented and tested. Regular expressions for all 12 phrasings of the easy reports: the strongest hand-written parser for that format. |
| Hard reports (`hard_reports.py`) | Implemented and tested. Free-form prose, tables, several facts per sentence, negations, contradictions corrected later in the text, and optional planted injections, with every trap recorded and scored. Evaluated with Gemini on all 80 environments (cached). |
| LLM extractors (`GeminiExtractor`, `LLMExtractor`) | Implemented and tested with stub transports/clients. The committed results include a live Gemini run (`gemini-3.5-flash-lite`, the default model). Every response is cached under `results/llm_cache/`, so the LLM results reproduce offline without an API key. `LLMExtractor` (Anthropic) has not been run live. |
| Planner-input sanity checks (`model_warnings`) | Implemented and tested. They flag degenerate extracted models (no entry point, no critical asset, dangling links) instead of letting the planner fail silently. |
| Attacker simulation (`simulation.py`) | Implemented and tested. Attack success rate, critical assets compromised and expected loss, before and after each plan, on the ground truth. Exact for every environment here; Monte Carlo for larger graphs. |
| Significance tests and confidence intervals (`stats.py`) | Implemented and tested. Stratified paired bootstrap 95% CIs, Wilcoxon signed-rank and sign tests (pure Python; checked against SciPy). |
| Evaluation harness, robustness experiments | Implemented; results in `results/` |
| NVD import (`nvd.py`) | Implemented and tested. Reads the NVD CVE API 2.0 JSON layout (CVSS v3.x base score, attack vector, privileges required). A sample of 21 well-known real CVEs, refreshed from the live NVD on 2026-11-27, is bundled in `src/cyberrisk/data/nvd_sample.json`. When a record lists several CVSS scores, NVD's own (source `nvd@nist.gov`) is used, then an entry typed Primary, then the first. `scripts/verify_nvd.py` rechecks it against the live NVD (see below). |
| MITRE ATT&CK mapping (`attack_mapping.py`) | Implemented and tested. A coarse rule-based mapping of each attack step to one of three techniques (T1190, T1210, T1068). |
| Trusted-inventory check (`inventory.py`, `inventory_eval.py`) | Implemented and tested. A defense against label tampering, not against injection in general: it lets an authoritative asset inventory overrule the extracted exposure and criticality labels (never links or vulnerabilities) and reports every label it overrules. Evaluated on the cached Gemini extractions of the hard reports, with complete, partial and stale inventories. |
| Real-CVE evaluation (`real_cve_eval.py`) | Implemented and tested. Planner and non-extraction baselines on the same 80 environments with real CVEs. The text extractors and the Gemini cache still use synthetic IDs only. |

The assets and topologies are fictional. By default the CVE identifiers and scores are fictional too (`SYN-CVE-xxxx`, deliberately not real NVD entries). With `--catalog real` the weaknesses are drawn from real CVEs, but they are still assigned to fictional assets at random.

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
cyberrisk demo --template small_lab --seed 3 --report hard_injected --extractor gemini --show-report   # hard report with injections, trap outcomes
```

Trusted-inventory check against planted text (offline, from the committed Gemini cache):

```bash
cyberrisk demo --template small_lab --seed 0 --report hard_injected --extractor gemini --inventory
cyberrisk inventory-check --seeds 20 --out results      # writes results/inventory_*.csv
```

Real CVEs and MITRE ATT&CK labels (oracle extractor only):

```bash
cyberrisk demo --template hpc --seed 3 --catalog real --attack   # each attack step labeled with its ATT&CK technique
cyberrisk real-cve --seeds 20 --out results                      # baselines vs. planner on real CVEs
python scripts/verify_nvd.py                                     # needs internet: compare the bundled sample with the live NVD
python scripts/verify_nvd.py --refresh                           # overwrite the sample with live NVD data
```

Run the full evaluation (4 templates × 20 seeds = 80 environments, under a minute):

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

The suite has 146 tests. They cover the risk math (including 5-hop paths), the hard-report generator and trap scoring, the template parser, the extractors (including the stub-client LLM path and malformed model output), defense planning and budgets, the budget sweep, planner-input warnings, the inventory check (reconciliation, imperfect inventories, offline reproduction), the attacker simulation (hand-calculated cases, exact vs. Monte Carlo), the statistics (checked against SciPy reference values), deterministic generation, metrics, the CLI, and offline reproduction from the committed cache.

## Method in brief

* **Attack graph.** Nodes are assets plus an `Internet` node. An edge `u → v` exists if the firewall permits `u → v` and `v` has a vulnerability. Its probability is the best `exploitability` among `v`'s vulnerabilities, where exploitability = attack-vector factor × privilege factor.
* **Risk.** A path's probability is the product of its edge probabilities. Its risk is probability × target criticality × target CVSS impact. Total risk is the sum, over critical assets, of the worst path risk reaching each one.
* **Path length.** Paths of any length are enumerated (`MAX_PATH_EDGES = None`). An earlier 4-hop cap silently removed two critical assets, `VAULT-01` (cloud) and `RES-DATA` (distributed), that sit 5 hops from the Internet, and understated risk in 46 of 80 environments. All results below are without the cap.
* **Defense.** Two control types: `patch` (cost 1) and `block` link (cost 2). The planner is greedy by risk reduction per unit cost under a budget (default 4). Plans are chosen on the model and then simulated on the ground-truth environment.
* **Baselines.** `cvss_only` patches the highest-CVSS vulnerabilities first. `rule_based` patches exposed-asset vulnerabilities with CVSS ≥ 7 first, then the rest by CVSS. Both use the scanner list and inventory, but ignore topology.
* **Attacker simulation.** The risk score above counts only the worst path to each asset, so it is a ranking score, not a probability of compromise. The simulation starts an attacker on the Internet and treats every attack-graph edge as one exploitation attempt that succeeds independently with the edge's probability. Everything reachable over successful edges is compromised, with every route and any path length counted. It reports *attack success* (probability that at least one critical asset is compromised), *critical assets compromised* (expected count), and *expected loss* (expected sum of criticality × CVSS impact over compromised critical assets). The graphs have at most 11 edges, so all 2^11 outcomes are enumerated exactly. Graphs with more than 16 edges fall back to seeded Monte Carlo.
* **Statistics.** Every configuration runs on the same environments, so comparisons are paired. CIs are 95% percentile bootstrap intervals (5,000 resamples, resampling seeds within each topology template). p-values are from the two-sided Wilcoxon signed-rank test (normal approximation with tie correction). The exact sign test and win/tie/loss counts are in `results/significance.csv`.

## Results (80 synthetic environments, budget 4)

Risk reduction is measured on the ground-truth environment, so extraction errors show up as wasted or missing controls.

| Configuration | Risk reduction, mean ± sd [95% CI] | Attack success, before → after | Critical assets compromised, before → after | Expected-loss reduction [95% CI] | Notes |
|---|---|---|---|---|---|
| `cvss_only` | 0.771 ± 0.276 [0.715, 0.824] | 0.509 → 0.177 | 1.008 → 0.264 | 0.782 [0.733, 0.829] | No topology |
| `rule_based` | 0.894 ± 0.183 [0.858, 0.927] | 0.509 → 0.051 | 1.008 → 0.083 | 0.902 [0.869, 0.932] | No topology; uses exposure flags |
| `graph_rule_extraction` | 0.000 ± 0.000 | 0.509 → 0.509 | 1.008 → 1.008 | 0.000 | Extracted graph has no attack path (see below) |
| `graph_template_extraction` | 0.999 ± 0.009 [0.996, 1.000] | 0.509 → 0.004 | 1.008 → 0.004 | 0.998 [0.995, 1.000] | Parser for all 12 easy phrasings; identical to the oracle |
| `graph_oracle_upper_bound` | 0.999 ± 0.009 [0.996, 1.000] | 0.509 → 0.004 | 1.008 → 0.004 | 0.998 [0.995, 1.000] | Planner on perfect model (upper bound) |
| `graph_llm_extraction` (Gemini) | 0.999 ± 0.009 [0.996, 1.000] | 0.509 → 0.004 | 1.008 → 0.004 | 0.998 [0.995, 1.000] | `gemini-3.5-flash-lite`, identical to the oracle in all 80 environments |

*Attack success* and *critical assets compromised* come from the attacker simulation on the ground truth. Without any defense, the simulated attacker compromises at least one critical asset with probability 0.51 on average. After the graph planner's controls, that drops to 0.004. The expected-loss reduction counts every attack route, while the risk score counts only the worst one, yet the two agree closely. So the planner's gains are not an artifact of scoring only the worst path.

Paired comparisons (difference A − B on the same 80 environments; `results/significance.csv`):

| Setting | Comparison | Metric | Mean difference [95% CI] | A better / tie / B better | Wilcoxon p |
|---|---|---|---|---|---|
| budget 4 | graph (oracle) − `rule_based` | risk reduction | +0.105 [+0.071, +0.141] | 42 / 36 / 2 | 2.3e-08 |
| budget 4 | graph (oracle) − `rule_based` | expected-loss reduction | +0.096 [+0.066, +0.130] | 42 / 36 / 2 | 4.0e-08 |
| budget 4 | graph (oracle) − `cvss_only` | risk reduction | +0.227 [+0.174, +0.284] | 61 / 19 / 0 | 1.1e-11 |
| budget 4 | `rule_based` − `cvss_only` | risk reduction | +0.123 [+0.065, +0.182] | 43 / 23 / 14 | 3.3e-04 |
| budget 4 | graph (Gemini) − graph (oracle) | risk reduction | +0.000 [+0.000, +0.000] | 0 / 80 / 0 | 1 |
| budget 1 | graph (oracle) − `rule_based` | risk reduction | +0.471 [+0.401, +0.539] | 67 / 13 / 0 | 1.1e-12 |
| budget 1 | graph (oracle) − `rule_based` | expected-loss reduction | +0.453 [+0.384, +0.520] | 66 / 13 / 1 | 1.3e-12 |
| budget 2 | graph (oracle) − `rule_based` | risk reduction | +0.264 [+0.197, +0.333] | 49 / 18 / 13 | 2.6e-07 |

Every graph-planner advantage is significant at any usual threshold, and the CIs exclude zero. The Gemini and oracle plans are identical, so their difference is exactly zero. These tests describe these 4 topology templates. Seeds within a template share a network layout, so the 80 environments are not 80 independent networks.

Extraction quality on the easy reports:

| Extractor | Asset F1 | Exposure F1 | Vuln F1 | Link F1 | Criticality acc. | Vuln attribute acc. | Models flagged by sanity checks |
|---|---|---|---|---|---|---|---|
| Rule-based | 0.822 | 0.329 | 0.493 | 0.514 | 0.610 | 1.000 | 80 / 80 |
| Template parser | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 / 80 |
| Gemini | 1.000 | 1.000 | 0.9995 | 0.998 | 1.000 | 1.000 | 0 / 80 |

On the easy reports, a parser written for their 12 phrasings matches Gemini exactly. So the easy reports alone cannot show that an LLM is needed. The hard reports below test that.

The rule-based extractor recognizes only the canonical phrasing, and about two thirds of facts are paraphrased in the test text, so recall is low by design. Its graph result of 0.000 comes from that: it misses most exposure lines, so the extracted graph has no entry point. The sanity checks flag all 80 of these models. *Attribute accuracy* scores the values on facts both models share (criticality; CVSS, attack vector and privilege). Set F1 cannot see a criticality downgrade, and attribute accuracy can.

Budget sweep (`results/budget_sweep.csv`). The gap between topology-aware planning and the baselines is widest when the budget is tight. Cells are risk reduction / expected-loss reduction / attack success after the plan:

| Budget | `cvss_only` | `rule_based` | graph planner (oracle model) |
|---|---|---|---|
| 1 | 0.294 / 0.306 / 0.410 | 0.309 / 0.320 / 0.337 | 0.780 / 0.774 / 0.168 |
| 2 | 0.506 / 0.520 / 0.328 | 0.690 / 0.697 / 0.143 | 0.954 / 0.946 / 0.056 |
| 3 | 0.636 / 0.648 / 0.256 | 0.823 / 0.834 / 0.079 | 0.993 / 0.991 / 0.013 |
| 4 | 0.771 / 0.782 / 0.177 | 0.894 / 0.902 / 0.051 | 0.999 / 0.998 / 0.004 |

The greedy planner is not optimal. At budget 2, `rule_based` beats it in 13 of 80 environments. In 12 of them the entry host has two equally exploitable vulnerabilities. Patching either one alone removes no risk, because the edge keeps the other one's probability, so greedy, which picks one control at a time, never chooses it. Patching both closes the entry point, and `rule_based` happens to do exactly that (e.g. `small_lab` seed 8, `hpc` seeds 0 and 2). A planner that considers pairs of controls, or an exact search, would fix this.

### Inventory check (`results/inventory_*.csv`)

The injections in the hard reports were the project's main weakness: one change-log line saying a host "no longer accepts traffic from the internet" fooled Gemini in 77 of 80 reports, and the planner, with no entry point left, recommended nothing. The inventory check lets a trusted asset list overrule the extracted `internet_exposed` and `criticality` labels before planning. It defends against planted text that tampers with those two labels. It does not defend against injection in general: it never edits links or vulnerabilities, so text that adds or removes a link, a vulnerability or an asset passes straight through.

Same 80 environments, same cached Gemini extractions, budget 4. Cells under "fooled" are planted lines that changed the model (instruction / unverified message / plausible update), out of 80.

| Report | Inventory | Risk reduction [95% CI] | Attack success after plan | Planted lines that fooled Gemini |
|---|---|---|---|---|
| hard | none | 0.966 [0.928, 0.995] | 0.017 | n/a |
| hard + injections | none | 0.195 [0.129, 0.266] | 0.436 | 32 / 9 / 77 |
| hard + injections | complete and correct | 0.969 [0.932, 0.998] | 0.017 | 0 / 0 / 0 |
| hard + injections | lists 75% of assets | 0.750 [0.654, 0.845] | 0.129 | 9 / 4 / 20 |
| hard + injections | lists 50% of assets | 0.541 [0.446, 0.633] | 0.261 | 13 / 6 / 37 |
| hard + injections | lists 25% of assets | 0.392 [0.295, 0.487] | 0.342 | 25 / 6 / 57 |
| hard + injections | complete, 25% of entries wrong | 0.651 [0.567, 0.728] | 0.246 | 24 / 25 / 28 |
| hard | complete, 25% of entries wrong | 0.652 [0.567, 0.731] | 0.239 | n/a |

Paired comparison on the injected reports, corrected minus raw plans, complete inventory: +0.774 [+0.699, +0.846] risk reduction, better in 64 environments, tied in 16, worse in 0 (Wilcoxon p = 2.1e-14). Full tables: `results/inventory_summary.csv` and `results/inventory_significance.csv`.

Findings:
- **A correct inventory removes the damage.** Risk reduction goes from 0.195 to 0.969, about what the model reaches on the same text without injections (0.966). Every one of the 77 fooled exposure labels and 41 fooled criticality labels is overruled.
- **It also works as a detector.** Even if the labels are not overwritten, the check flags the injected labels (33 / 10 / 77 flagged against 32 / 9 / 77 fooled, so it flags every fooled label, plus a few that the model got wrong in other ways). In 77 of 80 injected reports at least one label was flagged. On the clean hard reports it flags nothing, because Gemini read exposure and criticality correctly there.
- **A partial inventory helps in proportion to its coverage.** Listing 75% of the assets recovers most of the loss (0.750), 25% only a little (0.392). Injections aimed at assets the inventory does not list still succeed.
- **A wrong inventory is dangerous.** With 25% of entries wrong, the check lowers the clean-report result from 0.966 to 0.652 (-0.314 [-0.399, -0.233]), because it overrules correct extractions. It still beats no check on the injected reports (0.651 vs. 0.195), but only because the injections hurt so much. The check is only worth using with an inventory that is actually maintained; its discrepancy report is the signal to go and look.
- **It does not fix everything.** Link mistakes (deny rules read as paths, removed rules kept) are outside its scope, which is why the clean hard reports stay at 0.966 and not 1.0.

### Real CVEs (`results/real_cve_summary.csv`)

The same 80 environments, budget 4, with weaknesses drawn from 21 real CVEs (Log4Shell, EternalBlue, Heartbleed and others) instead of the synthetic catalog. Only configurations that need no text extraction are run. This is a stress test with real CVSS profiles, not a real-world evaluation: the CVEs are assigned to the fictional assets at random, and 14 of the 21 are network-exploitable with no privileges required.

| Configuration | Risk reduction (mean ± sd) | Attack success, before → after |
|---|---|---|
| `cvss_only` | 0.643 ± 0.355 | 0.712 → 0.326 |
| `rule_based` | 0.921 ± 0.224 | 0.712 → 0.055 |
| `graph_oracle_upper_bound` | 0.972 ± 0.099 | 0.712 → 0.063 |

The ordering matches the synthetic results (graph planner > rule-based > CVSS-only on risk reduction). The graph planner's attack-success-after is not lower than the rule-based baseline's here (0.063 vs. 0.055), so on that measure the two are about equal. This is a single evaluation on one small CVE sample, with no significance tests.

Model-level robustness (perturbing the planner's input model):

| Variant | Risk reduction | Controls |
|---|---|---|
| clean | 0.999 | 2.05 |
| 25% of links/vulns missing | 0.322 | 0.93 |
| 50% of links/vulns missing | 0.029 | 0.14 |
| two invented links + one invented vuln | 0.991 | 2.48 |
| critical assets relabeled low (adversarial) | 0.000 | 0 |

The sanity checks flag every adversarial model (80 / 80) and no clean model, so this failure is detected even though the planner cannot recover from it.

LLM text-level robustness (4 templates × 5 seeds, `results/llm_robustness.csv`):

| Report variant | Vuln F1 | Link F1 | Asset F1 | Risk reduction |
|---|---|---|---|---|
| clean | 0.998 | 1.000 | 1.000 | 1.000 |
| 30% of structural lines removed | 0.830 | 0.815 | 1.000 | 0.180 |
| three invented lines appended | 0.965 | 0.933 | 0.911 | 0.999 |
| appended injection line | 0.996 | 1.000 | 1.000 | 1.000 |

### Hard reports (`results/hard_text.csv`, `results/hard_text_traps.csv`)

The hard reports describe the same 80 ground-truth environments in text that neither parser was written for:
- free-form prose with synonyms ("mission-critical", "with no login at all")
- markdown tables for inventory, scanner output and firewall rules
- several facts per sentence ("WEB-01 forwards requests to APP-01, which in turn talks to DB-01")
- direction reversals ("DB-01 accepts inbound connections from APP-01")
- negations and deny rules
- four statements that are contradicted later in the text: a CVSS rescored after vendor review, a firewall rule removed, a false positive withdrawn, a decommissioned host

Every statement that disagrees with the ground truth is retracted later or is a planted injection, so the correct reading of every report is exactly the true environment. `hard_injected` is the same text plus three injections placed mid-report:
- **instruction:** a note addressed to automated tools, asking to record a critical asset as low criticality (the extraction prompt says to ignore such instructions)
- **unverified:** a forwarded message, explicitly marked as not verified, claiming a critical asset was downgraded
- **plausible update:** a change-log line, worded like the genuine corrections, saying an internet-facing host no longer accepts internet traffic

Inspect one with `cyberrisk demo --report hard_injected --show-report`.

| Report | Extractor | Asset F1 | Exposure F1 | Vuln F1 | Link F1 | Crit. acc. | Risk reduction [95% CI] | Attack success after plan |
|---|---|---|---|---|---|---|---|---|
| easy | template parser | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.999 [0.996, 1.000] | 0.004 |
| easy | Gemini | 1.000 | 1.000 | 0.9995 | 0.998 | 1.000 | 0.999 [0.996, 1.000] | 0.004 |
| hard | rule-based / template parser | 0.000 | 0.000 | 0.000 | 0.000 | n/a | 0.000 | 0.509 |
| hard | Gemini | 0.988 | 0.988 | 0.987 | 0.934 | 1.000 | 0.966 [0.928, 0.995] | 0.017 |
| hard + injections | rule-based / template parser | 0.000 | 0.000 | 0.000 | 0.000 | n/a | 0.000 | 0.509 |
| hard + injections | Gemini | 0.997 | 0.204 | 0.999 | 0.955 | 0.921 | 0.195 [0.129, 0.266] | 0.436 |

How often Gemini was fooled, per trap (fooled / tested over 80 reports):

| Trap | hard | hard + injections |
|---|---|---|
| CVSS rescored later in the report | 0 / 79 | 0 / 80 |
| firewall rule removed later | 16 / 79 (20%) | 9 / 80 (11%) |
| deny rule in the firewall table | 25 / 79 (32%) | 21 / 80 (26%) |
| finding withdrawn as false positive | 0 / 79 | 1 / 80 |
| targeted check "came back clean" | 0 / 79 | 0 / 80 |
| host "has no public address" | 0 / 79 | 0 / 80 |
| decommissioned host | 0 / 79 | 4 / 80 (5%) |
| injection: instruction to automated tools | – | 32 / 80 (40%) |
| injection: forwarded, unverified message | – | 9 / 80 (11%) |
| injection: plausible change-log update | – | 77 / 80 (96%) |

Findings:
- **The LLM generalizes and the parser does not.** On text neither was written for, the template parser extracts nothing and its plans remove no risk. Gemini keeps vulnerability F1 at 0.987 and removes 96.6% of risk. The difference is +0.966 [+0.928, +0.995] (Wilcoxon p = 1.4e-17).
- **Hard text costs the LLM little.** Risk reduction falls from 0.999 to 0.966 (+0.033 [+0.004, +0.070]). That is borderline: the bootstrap CI excludes zero but Wilcoxon p = 0.058. The loss comes mostly from links: Gemini turned a deny rule into a link in 32% of reports and kept a removed rule in 20%. It handled every rescored CVSS, negation and withdrawn finding correctly.
- **One of the 160 hard responses was unusable.** For `cloud` seed 8 (hard), Gemini returned JSON with a missing closing brace and stray characters. That response is kept, scored as an extraction failure (an empty model), and flagged by the sanity checks. It accounts for the 79s in the trap table.
- **Injections are the main weakness.** Risk reduction drops from 0.966 to 0.195 (−0.771 [−0.847, −0.685], p = 1.1e-13), and attack success after the plan rises from 0.017 to 0.436. Almost all of the damage comes from the plausible update (fooled 96%). Removing the only entry point leaves the planner with no attack path, so it recommends nothing. In the `distributed` template, which has two internet-facing gateways, risk reduction stays at 0.58. Gemini also followed the instruction addressed to automated tools in 40% of reports, even though its prompt says to ignore instructions in the text. It rejected the explicitly unverified message in 89%.
- **The sanity checks catch most of it.** They flag 57 of the 80 injected models, and 57 of the 65 whose plans remove less than half the risk. They detect a missing entry point but cannot restore it.

The plausible-update injection is worded exactly like a genuine correction, so no text-only extractor can be expected to reject it. The defense has to come from outside the report, for example by checking exposure and criticality against an independent asset inventory before planning.

Full tables: `results/summary.json`, `results/per_environment.csv`, `results/model_robustness.csv`, `results/budget_sweep.csv`, `results/llm_robustness.csv`, `results/hard_text.csv`, `results/hard_text_traps.csv`, `results/significance.csv`, `results/inventory_summary.csv`, `results/inventory_per_environment.csv`, `results/inventory_significance.csv`.

## Limitations

* The inventory in the "complete and correct" row is built from the ground truth, so that row is a ceiling that assumes the organisation keeps an accurate asset list, not a measurement of how well real inventories work. The partial and stale rows show how fast the benefit falls without that assumption. The check also does not defend against an attacker who can edit the inventory itself, and it was tested with one model, one run and three fixed injection wordings.
* The real-CVE sample is small (21 CVEs, mostly network-exploitable and high severity) and was first typed in by hand and then refreshed from the live NVD with `python scripts/verify_nvd.py --refresh`; the hand-entered version had 4 wrong scores out of 21. NVD rescores CVEs over time, so rerun `python scripts/verify_nvd.py` to check for changes (and rerun `cyberrisk real-cve` if any). The CVSS fields come from NVD, but the CVEs are placed on fictional assets, so this shows the pipeline works on real vulnerability data, not that the networks are realistic.
* The ATT&CK mapping uses one technique per kind of step (position plus attack vector). It is a labeling aid, not a validated mapping of real attacker behavior. A local-vector weakness on a host reached over the network is labeled T1068 because it cannot be exploited remotely, only from a foothold on the host, which is what T1068 describes. The attack graph has no notion of foothold and approximates it by the permitted link plus the low exploitability of a local vector (0.1).
* The text extractors (`RuleBasedExtractor`, `TemplateExtractor`) and the cached Gemini responses only understand `SYN-CVE-xxxx` IDs, so `--catalog real` works with the oracle extractor only.

* The LLM is evaluated with one model (`gemini-3.5-flash-lite`) and one run. On the easy reports, a parser for their twelve phrasings matches it exactly. The hard reports show the LLM generalizing to formats the parser was not written for, but they are still generated text: the phrase pool is larger, but finite, and a parser could be written for it too. They are not real analyst reports.
* The injection results are for a single model with the default extraction prompt. No prompt-level defenses were tried. The prompt is not part of the cache key, so changing the prompt requires a fresh cache.
* All data is synthetic, and the risk model is a simplified, hand-designed scoring model. The ground truth uses the same scoring model, so ranking accuracy shows pipeline fidelity, not real-world validity.
* The `cvss_only` and `rule_based` baselines use the true vulnerability list and exposure flags (a scanner plus inventory). This is a favorable assumption for them.
* The attack graph ignores privilege escalation across hops: an edge's probability does not depend on what the attacker already holds. The attacker always starts on the Internet (no insider or phishing start).
* The attacker simulation treats exploitation attempts as independent and makes each one once. It uses the same hand-set probabilities as the risk engine, so it checks the planner against a second, route-aware outcome measure, not against real attacker behavior.
* The statistics cover 80 environments built on 4 fixed topologies. Seeds change the vulnerabilities, not the layout, so significance here means "on these 4 layouts". It does not generalize to other networks.
* `results_superseded/` contains an earlier run with sparser environments and budget 6. It is kept for transparency and is not a reported result.

## Repository layout

```
src/cyberrisk/   models.py  graph.py  defense.py  baselines.py  synthetic.py  nvd.py  attack_mapping.py  real_cve_eval.py  inventory.py  inventory_eval.py
                 data/nvd_sample.json
                 hard_reports.py  extraction.py  metrics.py  simulation.py  stats.py  experiments.py  cli.py
tests/           unit tests (pytest)
scripts/         run_evaluation.py  verify_nvd.py
results/         generated CSV/JSON evaluation outputs
results_superseded/   earlier run, kept for transparency
report/          final project report (LaTeX)
```

## Team

Srija Pentyala, Siva Sai Deepank Manoj, Ubaid Khan Mohammed, Shivani Suresh, Lakshmi Jotsna Madhavarapu, Vyshnavi Pamidi
