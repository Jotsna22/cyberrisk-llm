"""Label attack-graph steps with MITRE ATT&CK techniques.

This is a deliberately coarse, rule-based mapping with one technique per kind of step,
chosen from the step's position and the vulnerability exploited:

  Internet -> exposed asset            T1190 Exploit Public-Facing Application   (Initial Access)
  internal hop, network/adjacent vuln  T1210 Exploitation of Remote Services      (Lateral Movement)
  hop using a local-vector vuln        T1068 Exploitation for Privilege Escalation (Privilege Escalation)

Why T1068 for a local-vector weakness on a host that is reached over the network: such a
weakness cannot be exploited from afar, only from a foothold on the host itself, which is
what T1068 describes. The attack graph has no notion of foothold; it approximates it by the
permitted link to the host and the low exploitability factor of a local vector (0.1), so the
label marks the step as "needs code execution on the target first", not as a remote exploit.

The vulnerability shown for a step is the one the risk engine scores: the destination's
most exploitable weakness (ties broken by higher CVSS, then CVE id).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import INTERNET, Environment, Vulnerability


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str

    def label(self) -> str:
        return f"{self.technique_id} {self.name}"


INITIAL_ACCESS = Technique("T1190", "Exploit Public-Facing Application", "Initial Access")
REMOTE_SERVICES = Technique("T1210", "Exploitation of Remote Services", "Lateral Movement")
PRIVILEGE_ESCALATION = Technique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")
TECHNIQUES = (INITIAL_ACCESS, REMOTE_SERVICES, PRIVILEGE_ESCALATION)


@dataclass(frozen=True)
class MappedStep:
    src: str
    dst: str
    vulnerability: Vulnerability | None
    technique: Technique | None


def step_vulnerability(env: Environment, dst: str) -> Vulnerability | None:
    """The weakness the risk engine uses for an attack step into `dst`."""
    asset = env.assets.get(dst)
    if asset is None or not asset.vulns:
        return None
    return min(asset.vulns.values(), key=lambda v: (-v.exploitability, -v.cvss, v.cve_id))


def technique_for_step(src: str, vuln: Vulnerability | None) -> Technique | None:
    if vuln is None:
        return None
    if src == INTERNET:
        return INITIAL_ACCESS
    if vuln.attack_vector == "local":
        return PRIVILEGE_ESCALATION
    return REMOTE_SERVICES


def map_path(env: Environment, nodes: tuple[str, ...] | list[str]) -> list[MappedStep]:
    steps = []
    for src, dst in zip(nodes, nodes[1:]):
        vuln = step_vulnerability(env, dst)
        steps.append(MappedStep(src, dst, vuln, technique_for_step(src, vuln)))
    return steps
