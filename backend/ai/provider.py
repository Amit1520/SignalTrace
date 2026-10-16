from typing import Protocol

from .models import Explanation, ExplanationEvidence


EXPLANATION_INSTRUCTION = (
    "You are explaining a precomputed cybersecurity behavioral incident. "
    "Do not perform detection. Use only supplied evidence. Do not invent facts. "
    "Clearly separate observed evidence from interpretation. State uncertainty when evidence is insufficient."
)


class LocalExplainer(Protocol):
    provider: str
    model_identifier: str

    def explain_incident(self, evidence: ExplanationEvidence) -> Explanation:
        """Return a validated explanation from structured local evidence only."""


class ModelUnavailableError(RuntimeError):
    pass


class ModelInferenceError(RuntimeError):
    pass
