"""Verify SignalTrace's real local GenAI provider against structured evidence.

No server, Sysmon collector, database, network service, or cloud AI provider is
started by this script. A local Llama GenAI package must already exist.
"""
from __future__ import annotations

from pathlib import Path

from backend.ai.genai_provider import OnnxRuntimeGenAIExplainer
from backend.ai.models import EvidenceItem, ExplanationEvidence, GenerationStatus


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    model_path = root / "models" / "llama-3.2-3b-instruct"
    evidence = ExplanationEvidence(
        incident_id="verification-incident",
        application_identity=".../powershell.exe",
        severity="medium",
        deviation_score=0.72,
        confidence=0.91,
        signals=[
            EvidenceItem(
                reference="verification-process",
                category="process",
                observation="PowerShell launched from an unusual parent process.",
                deviation="This parent-child relationship differs from the observed baseline.",
            )
        ],
        process_chain=[{"image_path": ".../powershell.exe"}],
        timeline=[],
        provenance_references=["verification-process"],
        known_limitations=["This is a synthetic verification incident."],
    )

    provider = OnnxRuntimeGenAIExplainer(model_path)
    explanation = provider.explain_incident(evidence)
    if explanation.generation_status is not GenerationStatus.GENERATED:
        raise SystemExit("Local GenAI provider did not return a generated explanation")
    print("LOCAL AI VERIFICATION: PASSED")
    print(f"Provider: {explanation.provider}")
    print(f"Model: {explanation.model_identifier}")
    print(f"Summary: {explanation.summary}")


if __name__ == "__main__":
    main()
