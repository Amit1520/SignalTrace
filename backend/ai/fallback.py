from datetime import datetime, timezone

from .models import Explanation, ExplanationEvidence, GenerationStatus, MAX_EXPLANATION_CHARS


class DeterministicFallbackExplainer:
    provider = "deterministic-fallback"
    model_identifier = "structured-evidence-1"

    def explain_incident(self, evidence: ExplanationEvidence) -> Explanation:
        changes = [item.observation for item in evidence.signals if item.observation]
        why = [item.deviation for item in evidence.signals if item.deviation]
        evidence_lines = [f"{item.reference}: {item.category}" for item in evidence.signals]
        recommendations = _recommendations(evidence)
        uncertainty = list(evidence.known_limitations)
        if not evidence.signals:
            uncertainty.append("No contributing signal details were supplied.")
        explanation = Explanation(
            incident_id=evidence.incident_id,
            summary=(
                f"Behavioral deviation was correlated for {evidence.application_identity}; "
                "this is not a threat determination."
            ),
            what_changed=changes[:10],
            why_unusual=why[:10],
            evidence=evidence_lines[:10],
            uncertainty=uncertainty[:10],
            recommended_investigation=recommendations,
            generated_at=datetime.now(timezone.utc),
            provider=self.provider,
            model_identifier=self.model_identifier,
            generation_status=GenerationStatus.FALLBACK,
        )
        if len(explanation.model_dump_json()) > MAX_EXPLANATION_CHARS:
            explanation.what_changed = explanation.what_changed[:3]
            explanation.why_unusual = explanation.why_unusual[:3]
            explanation.evidence = explanation.evidence[:3]
            explanation.uncertainty = explanation.uncertainty[:3]
        return explanation


def _recommendations(evidence: ExplanationEvidence) -> list[str]:
    categories = {item.category for item in evidence.signals}
    recommendations: list[str] = []
    if "process" in categories:
        recommendations.append("Review the newly observed process relationship and executable signature.")
    if "network" in categories:
        recommendations.append("Verify the observed destination and whether it matches a legitimate update or workflow.")
    if "file" in categories:
        recommendations.append("Inspect the observed file path and compare the activity with expected application behavior.")
    if not recommendations:
        recommendations.append("Compare the activity with a recent legitimate software change or update.")
    return recommendations
