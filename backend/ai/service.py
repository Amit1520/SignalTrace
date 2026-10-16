from __future__ import annotations

import re

from backend.incidents.models import Incident

from .evidence import build_explanation_evidence
from .fallback import DeterministicFallbackExplainer
from .models import (
    Explanation,
    ExplanationEvidence,
    ExplanationResult,
    GenerationStatus,
    MAX_EXPLANATION_CHARS,
)
from .provider import (
    LocalExplainer,
    ModelInferenceError,
    ModelUnavailableError,
)


class ExplanationService:
    def __init__(self, provider: LocalExplainer | None = None) -> None:
        self.provider = provider
        self.fallback = DeterministicFallbackExplainer()

    def explain(self, incident: Incident) -> ExplanationResult:
        evidence = build_explanation_evidence(incident)

        if self.provider is None:
            return ExplanationResult(
                explanation=self.fallback.explain_incident(evidence),
                generation_status=GenerationStatus.FALLBACK,
            )

        try:
            explanation = self.provider.explain_incident(evidence)

            if (
                len(explanation.model_dump_json())
                > MAX_EXPLANATION_CHARS
            ):
                raise ModelInferenceError(
                    "validated explanation exceeded the configured size limit"
                )

            _validate_grounding(
                explanation,
                evidence,
            )

            return ExplanationResult(
                explanation=explanation,
                generation_status=GenerationStatus.GENERATED,
            )

        except (
            ModelUnavailableError,
            ModelInferenceError,
            ValueError,
        ) as error:
            print("\n===== AI EXPLANATION FALLBACK =====")
            print(f"Error type: {type(error).__name__}")
            print(f"Error: {error}")
            print("===== END AI EXPLANATION FALLBACK =====\n")

            try:
                fallback = self.fallback.explain_incident(
                    evidence
                )

                return ExplanationResult(
                    explanation=fallback,
                    error=str(error),
                    generation_status=GenerationStatus.FALLBACK,
                )

            except Exception as fallback_error:
                return ExplanationResult(
                    error=(
                        "explanation failed: "
                        f"{fallback_error}"
                    ),
                    generation_status=GenerationStatus.FAILED,
                )


def _validate_grounding(
    explanation: Explanation,
    evidence: ExplanationEvidence,
) -> None:
    """
    Validate that factual model-generated explanation content
    is grounded in the structured incident evidence.

    The model is allowed to summarize evidence rather than repeat
    the complete raw observation verbatim.

    Supported grounding sources:
    - incident ID
    - application identity
    - evidence reference
    - evidence observation
    - evidence deviation
    - evidence category
    - category-based deviation phrases

    Uncertainty and recommended investigation are intentionally
    excluded from factual grounding validation because they are
    qualified interpretation/investigation guidance rather than
    claims about additional incident evidence.
    """

    allowed: set[str] = set()

    # Incident-level grounding.
    _add_grounding_token(
        allowed,
        evidence.incident_id,
    )

    _add_grounding_token(
        allowed,
        evidence.application_identity,
    )

    # Signal-level grounding.
    for item in evidence.signals:
        _add_grounding_token(
            allowed,
            item.reference,
        )

        _add_grounding_token(
            allowed,
            item.observation,
        )

        _add_grounding_token(
            allowed,
            item.deviation,
        )

        _add_grounding_token(
            allowed,
            item.category,
        )

        # Allow the LLM to naturally summarize a signal category.
        #
        # Example:
        #   category = "execution"
        #
        # Valid model wording:
        #   "Execution deviation evidence"
        #
        # This remains grounded because the phrase is derived
        # directly from the structured category.
        if item.category:
            category = _normalize_grounding_text(
                item.category
            )

            if category:
                allowed.add(
                    f"{category} deviation evidence"
                )

                allowed.add(
                    f"{category} behavioral deviation evidence"
                )

    # Only these sections contain factual claims that must be
    # grounded against incident evidence.
    grounded_sections = (
        (
            "evidence",
            explanation.evidence,
        ),
        (
            "what_changed",
            explanation.what_changed,
        ),
        (
            "why_unusual",
            explanation.why_unusual,
        ),
    )

    for section_name, section in grounded_sections:
        for text in section:
            normalized_text = _normalize_grounding_text(
                text
            )

            if not normalized_text:
                raise ModelInferenceError(
                    "model output contained empty "
                    f"unsupported {section_name}"
                )

            if not _contains_grounded_token(
                normalized_text,
                allowed,
            ):
                raise ModelInferenceError(
                    "model output contained unsupported evidence"
                )


def _add_grounding_token(
    allowed: set[str],
    value: str | None,
) -> None:
    """
    Add a normalized evidence token to the grounding set.
    """
    if not value:
        return

    normalized = _normalize_grounding_text(
        str(value)
    )

    if normalized:
        allowed.add(normalized)


def _normalize_grounding_text(
    value: str,
) -> str:
    """
    Normalize text for grounding comparison only.

    The original model output is never modified by this function.
    """

    text = str(value).strip().lower()

    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        text,
    )

    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def _contains_grounded_token(
    generated_text: str,
    allowed_tokens: set[str],
) -> bool:
    """
    Determine whether generated factual text contains a grounded
    evidence token.

    A generated sentence may contain additional explanatory
    wording around an explicitly grounded phrase.

    Example:

        "Execution deviation evidence suggests unusual behavior"

    is accepted when:

        "execution deviation evidence"

    is present in the structured grounding set.
    """

    for token in allowed_tokens:
        if not token:
            continue

        if token in generated_text:
            return True

    return False