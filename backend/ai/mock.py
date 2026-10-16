import json
from datetime import datetime, timezone

from .models import Explanation, ExplanationEvidence, GenerationStatus, MAX_EXPLANATION_CHARS
from .provider import ModelInferenceError


class MockLocalExplainer:
    provider = "mock-local"
    model_identifier = "mock-1"

    def __init__(self, response: str | dict | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error

    def explain_incident(self, evidence: ExplanationEvidence) -> Explanation:
        if self.error:
            raise ModelInferenceError(str(self.error)) from self.error
        response = self.response
        if response is None:
            response = {
                "incident_id": evidence.incident_id,
                "summary": "Structured behavioral deviation evidence was observed.",
                "what_changed": [item.observation for item in evidence.signals],
                "why_unusual": [item.deviation for item in evidence.signals],
                "evidence": [item.reference for item in evidence.signals],
                "uncertainty": evidence.known_limitations,
                "recommended_investigation": ["Review the supplied evidence against expected application behavior."],
                "provider": self.provider,
                "model_identifier": self.model_identifier,
                "generation_status": GenerationStatus.GENERATED,
            }
        if isinstance(response, str):
            if len(response) > MAX_EXPLANATION_CHARS:
                raise ModelInferenceError("model output exceeded the configured size limit")
            try:
                response = json.loads(response)
            except json.JSONDecodeError as error:
                raise ModelInferenceError("model output was not valid JSON") from error
        response.setdefault("incident_id", evidence.incident_id)
        response.setdefault("provider", self.provider)
        response.setdefault("model_identifier", self.model_identifier)
        response.setdefault("generated_at", datetime.now(timezone.utc))
        response.setdefault("generation_status", GenerationStatus.GENERATED)
        return Explanation.model_validate(response)
