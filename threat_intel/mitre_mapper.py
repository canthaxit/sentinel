"""
MITRE ATT&CK / ATLAS Mapping Utilities
Parses attack scenarios YAML and builds lookup tables.
"""

from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .config import MITRE_ATLAS_TECHNIQUES, OWASP_LLM_TOP10

try:
    from sentinel.frameworks import CWE_MAPPINGS as _CWE_MAPPINGS
except ImportError:
    _CWE_MAPPINGS = {}


class MITREMapper:
    """Maps attack scenarios to MITRE ATT&CK/ATLAS techniques."""

    def __init__(self, scenarios_path: Optional[str] = None):
        self._scenarios = []
        self._scenario_to_mitre = {}   # scenario_id -> [technique_ids]
        self._mitre_to_scenarios = {}  # technique_id -> [scenario_ids]
        self._scenario_to_owasp = {}   # scenario_id -> [owasp_ids]
        self._scenario_to_cwe = {}     # scenario_id -> [cwe_ids]
        self._scenario_metadata = {}   # scenario_id -> {name, category, ...}

        if scenarios_path is None:
            scenarios_path = str(
                Path(__file__).parent.parent / "AI_RED_TEAMING_ATTACK_SCENARIOS.yaml"
            )

        self._load_scenarios(scenarios_path)

    def _load_scenarios(self, path: str):
        """Load and parse attack scenarios YAML."""
        scenarios_file = Path(path)
        if not scenarios_file.exists():
            print(f"[THREAT-INTEL] Scenarios file not found: {path}")
            return

        if not HAS_YAML:
            # Fall back to manual parsing for basic fields
            self._load_scenarios_fallback(scenarios_file)
            return

        with open(scenarios_file, "r", encoding="utf-8") as f:
            self._scenarios = yaml.safe_load(f) or []

        self._build_lookups()

    def _load_scenarios_fallback(self, path: Path):
        """Minimal fallback parser when PyYAML is not available."""
        import re
        text = path.read_text(encoding="utf-8")

        # Extract scenario blocks
        current_id = None
        current_name = None
        current_category = None
        current_mitre = []
        current_owasp = []
        current_success_rate = ""
        current_severity = ""
        current_difficulty = ""

        for line in text.split("\n"):
            line = line.strip()

            if line.startswith("- id:"):
                # Save previous scenario
                if current_id:
                    self._save_scenario(
                        current_id, current_name, current_category,
                        current_mitre, current_owasp, current_success_rate,
                        current_severity, current_difficulty
                    )
                current_id = line.split(":", 1)[1].strip().strip('"')
                current_name = ""
                current_category = ""
                current_mitre = []
                current_owasp = []
                current_success_rate = ""
                current_severity = ""
                current_difficulty = ""
            elif line.startswith("name:"):
                current_name = line.split(":", 1)[1].strip().strip('"')
            elif line.startswith("category:"):
                current_category = line.split(":", 1)[1].strip()
            elif line.startswith("difficulty:"):
                current_difficulty = line.split(":", 1)[1].strip()
            elif line.startswith("severity:"):
                current_severity = line.split(":", 1)[1].strip()
            elif line.startswith("success_rate:"):
                current_success_rate = line.split(":", 1)[1].strip().strip('"')
            elif line.startswith("- T") and len(line) < 20:
                current_mitre.append(line.lstrip("- ").strip())
            elif line.startswith("- LLM"):
                current_owasp.append(line.lstrip("- ").strip())

        # Save last scenario
        if current_id:
            self._save_scenario(
                current_id, current_name, current_category,
                current_mitre, current_owasp, current_success_rate,
                current_severity, current_difficulty
            )

    def _save_scenario(self, sid, name, category, mitre, owasp,
                       success_rate, severity, difficulty):
        self._scenario_metadata[sid] = {
            "name": name,
            "category": category,
            "success_rate": success_rate,
            "severity": severity or "medium",
            "difficulty": difficulty,
        }
        self._scenario_to_mitre[sid] = mitre
        self._scenario_to_owasp[sid] = owasp
        # Derive CWE from category using canonical mapping
        self._scenario_to_cwe[sid] = list(_CWE_MAPPINGS.get(category, []))
        for tid in mitre:
            self._mitre_to_scenarios.setdefault(tid, []).append(sid)

    def _build_lookups(self):
        """Build lookup tables from parsed scenarios."""
        for scenario in self._scenarios:
            sid = scenario.get("id", "")
            if not sid:
                continue

            mitre = scenario.get("mitre_mapping", [])
            owasp = scenario.get("owasp_mapping", [])
            category = scenario.get("category", "")

            # CWE: use explicit cwe_mapping if present, else derive from category
            cwe = scenario.get("cwe_mapping", [])
            if not cwe and category:
                cwe = list(_CWE_MAPPINGS.get(category, []))

            self._scenario_metadata[sid] = {
                "name": scenario.get("name", ""),
                "category": category,
                "success_rate": scenario.get("success_rate", ""),
                "severity": scenario.get("severity", "medium"),
                "difficulty": scenario.get("difficulty", ""),
            }

            self._scenario_to_mitre[sid] = mitre
            self._scenario_to_owasp[sid] = owasp
            self._scenario_to_cwe[sid] = cwe

            for tid in mitre:
                self._mitre_to_scenarios.setdefault(tid, []).append(sid)

    def get_techniques_for_scenario(self, scenario_id: str) -> List[str]:
        """Get MITRE technique IDs for a given attack scenario."""
        return self._scenario_to_mitre.get(scenario_id, [])

    def get_scenarios_for_technique(self, technique_id: str) -> List[str]:
        """Get attack scenario IDs that map to a given MITRE technique."""
        return self._mitre_to_scenarios.get(technique_id, [])

    def get_owasp_for_scenario(self, scenario_id: str) -> List[str]:
        """Get OWASP LLM Top 10 mappings for a scenario."""
        return self._scenario_to_owasp.get(scenario_id, [])

    def get_cwe_for_scenario(self, scenario_id: str) -> List[str]:
        """Get CWE IDs for a scenario.

        Uses explicit cwe_mapping from YAML if available, otherwise
        derives CWE IDs from the scenario's attack category via
        sentinel.frameworks.CWE_MAPPINGS.
        """
        return self._scenario_to_cwe.get(scenario_id, [])

    def get_scenario_metadata(self, scenario_id: str) -> Dict:
        """Get metadata for a scenario."""
        return self._scenario_metadata.get(scenario_id, {})

    def get_all_scenarios(self) -> Dict[str, Dict]:
        """Get all scenario metadata."""
        return dict(self._scenario_metadata)

    def get_technique_name(self, technique_id: str) -> str:
        """Get human-readable name for a MITRE technique."""
        tech = MITRE_ATLAS_TECHNIQUES.get(technique_id, {})
        return tech.get("name", technique_id)

    def get_owasp_name(self, owasp_id: str) -> str:
        """Get name for an OWASP mapping."""
        return OWASP_LLM_TOP10.get(owasp_id, owasp_id)

    def get_coverage(self, detected_techniques: Optional[List[str]] = None) -> Dict:
        """
        Calculate MITRE technique coverage.

        Args:
            detected_techniques: List of technique IDs with detections.
                If None, uses all techniques that have scenario mappings.

        Returns:
            Dict with coverage stats per technique.
        """
        all_techniques = set()
        for tids in self._scenario_to_mitre.values():
            all_techniques.update(tids)

        if detected_techniques is None:
            detected_techniques = list(all_techniques)

        detected_set = set(detected_techniques)

        coverage = {}
        for tid in sorted(all_techniques):
            scenarios = self._mitre_to_scenarios.get(tid, [])
            coverage[tid] = {
                "name": self.get_technique_name(tid),
                "tactic": MITRE_ATLAS_TECHNIQUES.get(tid, {}).get("tactic", "unknown"),
                "scenarios": scenarios,
                "scenario_count": len(scenarios),
                "detected": tid in detected_set,
            }

        total = len(all_techniques)
        detected_count = len(all_techniques & detected_set)

        return {
            "techniques": coverage,
            "total_techniques": total,
            "detected_techniques": detected_count,
            "coverage_percent": (detected_count / total * 100) if total > 0 else 0.0,
        }
