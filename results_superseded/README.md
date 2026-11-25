# Superseded evaluation run

`v0_sparse_budget6/` is the first full evaluation run. It is kept for transparency and is **not** the reported result.

It used two settings that made the comparison uninformative:

* Some assets had zero vulnerabilities, so most critical assets were unreachable (on average under 0.5 at-risk assets per environment).
* The defense budget was 6, which let the CVSS-only baseline patch nearly every vulnerability.

The generator was changed so that every asset carries 1-3 vulnerabilities, and the budget was reduced to 4. The changes were made after inspecting this run for degenerate output (zero at-risk assets, and baselines that patched almost everything). They were not chosen by comparing which configuration scored best, but they were made after seeing this run's numbers, which is a limitation. The results in `results/` come from the revised configuration.
