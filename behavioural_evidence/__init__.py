"""Dataset V2-compatible behavioural evidence framework (Task 22).

Evidence comes only from observable Cowrie JSON telemetry. The framework records which versioned indicators matched,
with the exact source line, simple command and token; derives attempt-worded interpretations that each need an action
indicator; assigns a count-based evidence level E0-E3; and abstains explicitly. It never uses DEC cluster identities,
the legacy V1 signature catalogue, attack probabilities, or statistical novelty as behavioural evidence.

Design: reports/behavioural_evidence_framework_design_20261111/ (catalogue amended to v2-evidence-1.1, see
catalogue.AMENDMENTS).
"""
from .catalogue import CATALOGUE_VERSION, INDICATORS, INTERPRETATIONS
from .engine import EvidenceEngine, EvidenceConfig
from .errors import CatalogueError, SchemaError, AttributionError

__all__ = ["CATALOGUE_VERSION", "INDICATORS", "INTERPRETATIONS", "EvidenceEngine", "EvidenceConfig",
           "CatalogueError", "SchemaError", "AttributionError"]
