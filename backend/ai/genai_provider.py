"""Local generative-AI provider using ONNX Runtime GenAI.

The provider is deliberately model-folder based. The same SignalTrace interface can
load a CPU model during development or a Qualcomm/QNN-prepared model on a
Windows-on-Snapdragon deployment, because the model's ``genai_config.json``
defines the execution path.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Explanation, ExplanationEvidence, GenerationStatus
from .provider import (
    EXPLANATION_INSTRUCTION,
    LocalExplainer,
    ModelInferenceError,
    ModelUnavailableError,
)


DEFAULT_MAX_NEW_TOKENS = 192
DEFAULT_TEMPERATURE = 0.0
DEFAULT_TOP_P = 1.0
DEFAULT_CONTEXT_LIMIT = 4096

# ---------------------------------------------------------------------------
# NOTE on the split below (read this before touching the prompt again):
#
# Only "evidence", "what_changed" and "why_unusual" are grounding-checked by
# service.py's _validate_grounding(). A small local model will reliably drift
# into generic filler ("behavioral deviation evidence") for exactly those
# fields no matter how the prompt forbids it -- prompt wording alone is not
# a reliable enough control for a model this size.
#
# So those three fields are no longer written by the model at all. They are
# built here directly from evidence.signals, using the same literal strings
# (item.observation, item.deviation, item.category) that _validate_grounding
# already treats as grounded. This makes grounding failures for those fields
# structurally impossible rather than something to catch after generation.
#
# The model still authors "summary", "uncertainty" and
# "recommended_investigation" -- fields service.py's validator intentionally
# does not grounding-check -- so real model value is kept where it is safe.
# ---------------------------------------------------------------------------

# Fields the model is asked for and that are used verbatim (after cleanup).
_MODEL_LIST_FIELDS = ("uncertainty", "recommended_investigation")

_FIELD_LIMITS = {
    "what_changed": 2,
    "why_unusual": 2,
    "evidence": 3,
    "uncertainty": 2,
    "recommended_investigation": 2,
}

# Defence in depth for the two fields the model still writes freely: even
# though they are not fed to _validate_grounding, they must never assert a
# verdict or suggest remediation.
_VERDICT_PATTERN = re.compile(
    r"\b(is|are|was|were|being)\s+(definitely\s+|clearly\s+|likely\s+)?"
    r"(malware|malicious|a virus|ransomware|a trojan|compromised|an attack)\b"
    r"|\bconfirmed (malware|compromise|attack|breach)\b",
    re.IGNORECASE,
)

_REMEDIATION_PATTERN = re.compile(
    r"\b(terminate|kill|delete|remove|quarantine|block|uninstall|wipe|"
    r"reformat|disable|shut ?down|isolate)\b",
    re.IGNORECASE,
)


class OnnxRuntimeGenAIExplainer(LocalExplainer):
    """Generate grounded incident explanations with ONNX Runtime GenAI."""

    provider = "onnxruntime-genai"

    def __init__(
        self,
        model_path: Path,
        *,
        max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
        genai_module: Any | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.max_new_tokens = max(64, min(max_new_tokens, 512))
        self.temperature = max(0.0, min(temperature, 1.0))
        self.top_p = max(0.1, min(top_p, 1.0))
        self._og = genai_module

        if not self.model_path.is_dir():
            raise ModelUnavailableError(
                f"local GenAI model directory is unavailable: {self.model_path}"
            )

        if not (self.model_path / "genai_config.json").is_file():
            raise ModelUnavailableError(
                "GenAI model directory is missing genai_config.json: "
                f"{self.model_path}"
            )

        try:
            if self._og is None:
                import onnxruntime_genai as og

                self._og = og

            # ONNX Runtime GenAI expects the model DIRECTORY.
            self.model = self._og.Model(str(self.model_path))
            self.tokenizer = self._og.Tokenizer(self.model)
            self.model_identifier = self._read_model_identifier()

        except ImportError as error:
            raise ModelUnavailableError(
                "onnxruntime-genai is not installed; install the SignalTrace "
                "GenAI optional dependency"
            ) from error

        except ModelUnavailableError:
            raise

        except Exception as error:
            raise ModelInferenceError(
                f"local GenAI model initialization failed: {error}"
            ) from error

    def _read_model_identifier(self) -> str:
        try:
            config = json.loads(
                (self.model_path / "genai_config.json").read_text(
                    encoding="utf-8"
                )
            )

            model = config.get("model", {}) if isinstance(config, dict) else {}
            name = model.get("name") if isinstance(model, dict) else None

            if name:
                return str(name)

        except Exception:
            pass

        return self.model_path.name

    def _format_prompt(self, prompt: str) -> str:
        """Use the model's native chat template when available."""

        template_path = self.model_path / "tokenizer_config.json"

        try:
            config = json.loads(
                template_path.read_text(encoding="utf-8")
            )

            template = (
                config.get("chat_template")
                if isinstance(config, dict)
                else None
            )

            if (
                isinstance(template, str)
                and template.strip()
                and hasattr(self.tokenizer, "apply_chat_template")
            ):
                messages = [
                    {
                        "role": "system",
                        "content": (
                            "You are SignalTrace's local cybersecurity incident "
                            "explanation component. "
                            "Use only the supplied evidence. "
                            "Do not invent evidence. "
                            "Return exactly one compact JSON object. "
                            "Do not add commentary after the JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ]

                return self.tokenizer.apply_chat_template(
                    template,
                    messages,
                    add_generation_prompt=True,
                )

        except Exception:
            # Fall back to the plain prompt for model/runtime combinations
            # without compatible chat-template support.
            pass

        return prompt

    def explain_incident(
        self,
        evidence: ExplanationEvidence,
    ) -> Explanation:
        prompt = build_incident_prompt(evidence)

        try:
            prompt = self._format_prompt(prompt)

            params = self._og.GeneratorParams(self.model)

            input_tokens = self.tokenizer.encode(prompt)

            # Keep the total context bounded.
            max_length = min(
                DEFAULT_CONTEXT_LIMIT,
                len(input_tokens) + self.max_new_tokens,
            )

            params.set_search_options(
                max_length=max_length,
                temperature=self.temperature,
                top_p=self.top_p,
                do_sample=False,
            )

            generator = self._og.Generator(self.model, params)
            generator.append_tokens(input_tokens)

            stream = self.tokenizer.create_stream()
            chunks: list[str] = []

            while not generator.is_done():
                generator.generate_next_token()

                tokens = generator.get_next_tokens()

                if not tokens:
                    continue

                for token in tokens:
                    chunks.append(stream.decode(token))

            raw = "".join(chunks).strip()

            print("\n===== RAW MODEL OUTPUT =====")
            print(repr(raw))
            print("===== END RAW MODEL OUTPUT =====\n")

            del generator

            payload = _parse_json_object(raw)

            return _build_explanation(
                payload,
                evidence,
                self.provider,
                self.model_identifier,
            )

        except ModelInferenceError:
            raise

        except Exception as error:
            raise ModelInferenceError(
                f"local GenAI inference failed: {error}"
            ) from error


def build_incident_prompt(
    evidence: ExplanationEvidence,
) -> str:
    """Create a compact deterministic prompt from structured evidence.

    SignalTrace keeps the complete evidence internally. Only a compact,
    deduplicated representation is sent to the language model.

    The model is asked only for "summary", "uncertainty" and
    "recommended_investigation" -- the fields service.py's grounding
    validator does not check. "what_changed", "why_unusual" and "evidence"
    are built directly from the structured evidence after generation (see
    _build_explanation), so they are never model-authored text.
    """

    compact_signals: list[dict[str, str]] = []
    seen_signals: set[tuple[str, str, str]] = set()

    for signal in evidence.signals:
        observation = signal.observation.strip()
        deviation = signal.deviation.strip()
        category = signal.category.strip()
        reference = signal.reference.strip()

        # Deduplicate identical observations/deviations while retaining
        # category differences.
        key = (
            category,
            observation,
            deviation,
        )

        if key in seen_signals:
            continue

        seen_signals.add(key)

        compact_signals.append(
            {
                "reference": reference,
                "category": category,
                "observation": observation,
                "deviation": deviation,
            }
        )

        # The model does not need an exhaustive list.
        if len(compact_signals) >= 6:
            break

    compact_process_chain = [
        {
            "process_guid": item.get("process_guid"),
            "parent_guid": item.get("parent_guid"),
            "process_id": item.get("process_id"),
            "image_path": item.get("image_path"),
        }
        for item in evidence.process_chain[:6]
    ]

    compact_provenance = list(
        dict.fromkeys(evidence.provenance_references)
    )[:6]

    compact_evidence = {
        "incident_id": evidence.incident_id,
        "application_identity": evidence.application_identity,
        "severity": evidence.severity,
        "deviation_score": evidence.deviation_score,
        "confidence": evidence.confidence,
        "signals": compact_signals,
        "process_chain": compact_process_chain,
        "provenance_references": compact_provenance,
        "known_limitations": evidence.known_limitations,
    }

    evidence_json = json.dumps(
        compact_evidence,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return (
        f"{EXPLANATION_INSTRUCTION}\n\n"

        "ROLE:\n"
        "You are SignalTrace's local cybersecurity incident explanation "
        "component.\n"
        "The deterministic SignalTrace security pipeline has already performed "
        "detection and incident correlation, and has already produced the "
        "factual evidence list. Another system component will attach the "
        "factual evidence to your answer automatically.\n"
        "Your ONLY task is to write a short summary and investigation "
        "guidance. The reader may have NO technical or security "
        "background at all -- write for that reader.\n\n"

        "SUMMARY FORMAT (required):\n"
        "The summary MUST name the specific application (use the exact "
        "application_identity value given below) and MUST state the "
        "severity as one plain word: low, medium, or high. Use this "
        "pattern: \"[application] was flagged as [severity] severity "
        "because [one short reason].\" Do not omit the application name "
        "or the severity word for any reason.\n"
        "The reason you give MUST include the same concrete detail shown "
        "in the evidence below (the specific program name involved, or the "
        "specific time of day, whichever the evidence names) -- do not "
        "generalize it away into a vague phrase like \"started up\" or "
        "\"behaved unusually\". If the evidence names a program, that "
        "program\'s name must appear in your reason.\n"
        "Do not simply copy an evidence sentence word-for-word as your "
        "reason. Add one brief clause of interpretation beyond the raw "
        "fact -- for example, note whether several occurrences happened "
        "close together (suggesting one trigger) or spread out (suggesting "
        "repeated behavior), or note that the detail is minor/unremarkable "
        "if severity is low. The summary should feel like a short "
        "explanation of the fact, not a restatement of it.\n\n"

        "TONE BY SEVERITY (required):\n"
        "Match the urgency of your summary and recommended_investigation to "
        "the actual severity given below -- do not use the same urgent "
        "tone for every severity level.\n"
        "- low or normal severity: calm, low-stakes tone. Example "
        "recommended_investigation style: \"This is minor and not urgent, "
        "but worth a glance when convenient.\"\n"
        "- medium severity: moderate tone. Example style: \"Worth checking "
        "with your IT or security team when you get a chance, to confirm "
        "this was expected.\"\n"
        "- high severity: direct, prompt tone, still calm and never "
        "alarmist. Example style: \"Check with your IT or security team "
        "soon to confirm this was expected.\"\n\n"

        "SOURCE OF TRUTH:\n"
        "Use ONLY the supplied incident evidence.\n"
        "Never invent facts.\n"
        "Never infer unsupported processes, users, files, network "
        "connections, commands, or causes.\n\n"

        "PLAIN LANGUAGE RULES:\n"
        "- Write in simple, everyday words a non-technical person can "
        "follow.\n"
        "- Never use the words \"temporal\", \"execution\", \"deviation "
        "score\", \"behavioral deviation\", \"anomaly\", or any other "
        "internal category or field name.\n"
        "- Never include a raw decimal number, percentage, or score (for "
        "example, never write something like 0.4549999999999996). If you "
        "want to convey severity, use a plain word instead, such as "
        "\"low\", \"medium\", or \"high\".\n"
        "- Never include a hash, ID, or file path in the summary.\n"
        "- Explain what happened and why it was flagged the way you would "
        "explain it to a coworker with no security background.\n\n"

        "OUTPUT:\n"
        "Return exactly ONE JSON object.\n"
        "Return nothing before the opening brace.\n"
        "Return nothing after the closing brace.\n"
        "Do not use Markdown.\n"
        "Do not use code fences.\n"
        "Do not explain the JSON.\n\n"

        "EXACT JSON SHAPE:\n"
        "{"
        '"summary":"string",'
        '"uncertainty":["string"],'
        '"recommended_investigation":["string"]'
        "}\n\n"

        "STRICT SIZE RULES:\n"
        "- summary: exactly 1 short sentence.\n"
        "- uncertainty: 1 or 2 items maximum.\n"
        "- recommended_investigation: 1 or 2 items maximum.\n"
        "- Keep every item short.\n"
        "- Never repeat an item.\n"
        "- Finish the JSON immediately.\n\n"

        "GROUNDING RULES:\n"
        "- Use ONLY facts present in the supplied evidence.\n"
        "- Do not invent a cause.\n"
        "- Do not call the incident malware.\n"
        "- Do not claim compromise unless the supplied evidence explicitly "
        "states it.\n"
        "- uncertainty must describe limitations or uncertainty actually "
        "supported by the supplied evidence, in plain words.\n"
        "- recommended_investigation must be passive review guidance a "
        "non-technical person could still follow, such as \"check with your "
        "IT or security team\" -- not a technical command or tool name.\n"
        "- Do not recommend executing commands or taking autonomous action, "
        "and never recommend killing, deleting, quarantining, blocking or "
        "uninstalling anything.\n\n"

        "IMPORTANT:\n"
        "Do not copy the entire evidence object into the answer.\n"
        "Do not use the internal JSON structure as narrative content.\n\n"

        f"INCIDENT EVIDENCE:\n{evidence_json}\n\n"
        "RETURN JSON NOW:"
    )


def _try_load(text: str) -> dict[str, Any] | None:
    """Attempt json.loads without raising."""

    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None

    return value if isinstance(value, dict) else None


def _extract_first_json_object(
    text: str,
    start: int,
) -> str | None:
    """Extract the first complete JSON object.

    Handles strings and escaped characters correctly and tolerates a missing
    closing array bracket immediately before a closing object brace.
    """

    stack: list[str] = []
    in_string = False
    escape = False
    repaired: list[str] = []

    i = start
    n = len(text)

    while i < n:
        ch = text[i]

        if in_string:
            repaired.append(ch)

            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False

            i += 1
            continue

        if ch == '"':
            in_string = True
            repaired.append(ch)
            i += 1
            continue

        if ch == "{":
            stack.append("}")
            repaired.append(ch)
            i += 1
            continue

        if ch == "[":
            stack.append("]")
            repaired.append(ch)
            i += 1
            continue

        if ch in "}]":
            while (
                stack
                and stack[-1] != ch
                and stack[-1] == "]"
            ):
                repaired.append("]")
                stack.pop()

            if not stack or stack[-1] != ch:
                return None

            repaired.append(ch)
            stack.pop()

            if not stack:
                return "".join(repaired)

            i += 1
            continue

        repaired.append(ch)
        i += 1

    return None


def _parse_json_object(raw: str) -> dict[str, Any]:
    """Extract the first usable JSON object from model output."""

    if not isinstance(raw, str):
        raise ModelInferenceError(
            "model output was not text"
        )

    text = raw.strip()

    if not text:
        raise ModelInferenceError(
            "model output was empty"
        )

    start = text.find("{")

    if start < 0:
        raise ModelInferenceError(
            "model output was not valid JSON"
        )

    # First attempt: proper bracket-aware extraction.
    candidate = _extract_first_json_object(
        text,
        start,
    )

    if candidate is not None:
        value = _try_load(candidate)

        if value is not None:
            return value

    # Second attempt: progressively consider each closing brace.
    tail = text[start:]

    for index, character in enumerate(tail):
        if character != "}":
            continue

        prefix = tail[: index + 1].strip()

        candidates = [
            prefix,

            # Remove a stray quote immediately before the final brace.
            re.sub(
                r'"\s*}$',
                "}",
                prefix,
            ),

            # Remove a trailing comma before the final brace.
            re.sub(
                r",\s*}$",
                "}",
                prefix,
            ),
        ]

        for candidate_text in candidates:
            value = _try_load(candidate_text)

            if value is not None:
                return value

    raise ModelInferenceError(
        "model output was not valid JSON"
    )


def _clean_string_list(value: Any, limit: int) -> list[str]:
    """Normalize a model-provided list field: strings only, deduped, capped."""

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, list):
        return []

    cleaned: list[str] = []
    seen: set[str] = set()

    for item in value:
        if not isinstance(item, str):
            continue

        item = item.strip()

        if not item:
            continue

        key = item.casefold()

        if key in seen:
            continue

        seen.add(key)
        cleaned.append(item)

    return cleaned[:limit]


# Words that, appearing shortly before a matched verdict/remediation phrase,
# mean the sentence is denying or cautioning against it rather than
# asserting or recommending it (e.g. "not a determination that ... is
# malware", "do not uninstall anything"). Checked only in the words
# immediately before the match -- see _is_negated().
_NEGATION_WORDS = {
    "not", "never", "no", "without", "cannot", "can't", "won't", "shouldn't",
    "isn't", "aren't", "wasn't", "weren't", "doesn't", "don't", "didn't",
}
_NEGATION_LOOKBACK_WORDS = 6


def _is_negated(text: str, match_start: int) -> bool:
    """True if a negation word appears in the few words before match_start."""

    before = text[:match_start]
    words = re.findall(r"[A-Za-z']+", before)[-_NEGATION_LOOKBACK_WORDS:]
    return any(word.lower() in _NEGATION_WORDS for word in words)


def _ensure_summary_names_app_and_severity(
    summary: str,
    evidence: ExplanationEvidence,
) -> str:
    """Guarantee the app name and a plain severity word appear in the summary.

    Small local models do not reliably follow a formatting instruction (this
    has already been observed with other rules in this prompt), so this is
    enforced in code rather than trusted from the prompt alone. If either is
    missing, the summary is replaced with a deterministic sentence built
    from the evidence itself -- never left to guesswork about the model's
    intent.
    """

    app_name = (evidence.application_identity or "").strip()
    # Compare against just the file name (e.g. "powershell.exe"), not the
    # full redacted path (e.g. ".../powershell/powershell.exe") -- the
    # model naming the executable correctly should count as present even
    # though it never sees or repeats the redacted directory prefix.
    app_basename = app_name.replace("\\", "/").rsplit("/", 1)[-1]
    # Also accept the name without its extension (e.g. "notepad" for
    # "notepad.exe") -- a model saying the plain name is still naming the
    # application correctly, and should not trigger an unnecessary rebuild
    # of an otherwise good summary.
    app_stem = app_basename.rsplit(".", 1)[0] if "." in app_basename else app_basename
    severity = (evidence.severity or "").strip().lower()

    summary_lower = summary.lower()
    app_present = bool(app_basename) and (
        app_basename.lower() in summary_lower
        or (bool(app_stem) and app_stem.lower() in summary_lower)
    )
    severity_present = bool(severity) and severity in summary_lower

    if app_present and severity_present:
        return summary

    severity_word = severity or "unknown"
    app_label = app_basename or app_name or "This application"
    return (
        f"{app_label} was flagged as {severity_word} severity because its "
        "recent activity does not match its usual pattern."
    )


def _reject_unsafe_text(texts: list[str]) -> None:
    """Reject an unhedged threat verdict or remediation advice.

    "summary", "uncertainty" and "recommended_investigation" are not
    grounding-checked by service.py, so this is the control that keeps them
    safe: no verdicts, no instructions to kill/delete/quarantine anything.

    A match preceded by a negation word (see _NEGATION_WORDS) within the
    last few words is treated as the sentence denying or cautioning against
    the phrase -- for example "not a determination that anything is
    malware" or "do not uninstall the application" -- and is allowed. This
    text is explanatory only and is never fed back into an action, so
    erring toward allowing a clearly hedged sentence is the safer trade-off
    against silently discarding a correct, safety-relevant disclaimer.
    """

    for text in texts:
        for match in _VERDICT_PATTERN.finditer(text):
            if not _is_negated(text, match.start()):
                raise ModelInferenceError(
                    "model output asserted a threat verdict"
                )

        for match in _REMEDIATION_PATTERN.finditer(text):
            if not _is_negated(text, match.start()):
                raise ModelInferenceError(
                    "model output recommended remediation action"
                )


def _evidence_derived_fields(
    evidence: ExplanationEvidence,
) -> dict[str, list[str]]:
    """Build what_changed / why_unusual / evidence directly from evidence.

    These three are the only fields service.py's _validate_grounding checks.
    Building them here, from the literal strings the validator already
    trusts (item.observation, item.deviation, item.reference/item.category),
    guarantees they pass grounding -- the model never gets a chance to
    phrase them into something ungrounded.
    """

    what_changed: list[str] = []
    why_unusual: list[str] = []
    evidence_lines: list[str] = []
    seen_observation: set[str] = set()
    seen_deviation: set[str] = set()
    seen_evidence_line: set[str] = set()

    for item in evidence.signals:
        observation = item.observation.strip()
        deviation = item.deviation.strip()
        # Reuses the same already-grounded observation text as
        # what_changed, rather than inventing new wording (e.g. a
        # friendly category label) that service.py's _validate_grounding
        # has no way to recognise -- that check only trusts item.reference,
        # item.observation, item.deviation, item.category and the exact
        # canned "{category} deviation evidence" phrase built from the raw
        # category word, nothing else.
        evidence_line = observation

        if observation and observation.casefold() not in seen_observation:
            seen_observation.add(observation.casefold())
            what_changed.append(observation)

        if deviation and deviation.casefold() not in seen_deviation:
            seen_deviation.add(deviation.casefold())
            why_unusual.append(deviation)

        if evidence_line.casefold() not in seen_evidence_line:
            seen_evidence_line.add(evidence_line.casefold())
            evidence_lines.append(evidence_line)

    return {
        "what_changed": what_changed[: _FIELD_LIMITS["what_changed"]],
        "why_unusual": why_unusual[: _FIELD_LIMITS["why_unusual"]],
        "evidence": evidence_lines[: _FIELD_LIMITS["evidence"]],
    }


# Used only when the model supplies no recommended_investigation text at
# all (empty/missing after cleanup). Tiered by severity so a "low" incident
# does not read with the same urgency as a "high" one -- the model is also
# asked to match this tone in the prompt (see TONE BY SEVERITY), but this is
# the guaranteed fallback when it does not.
_DEFAULT_INVESTIGATION_BY_SEVERITY = {
    "normal": "No action is needed; this looks like routine background activity.",
    "low": "This is minor and not urgent, but worth a glance when convenient.",
    "medium": "Worth checking with your IT or security team when you get a "
              "chance, to confirm this was expected.",
    "high": "Check with your IT or security team soon to confirm this was "
            "expected.",
}


def _default_investigation(severity: str) -> str:
    return _DEFAULT_INVESTIGATION_BY_SEVERITY.get(
        (severity or "").strip().lower(),
        "Passively review the application's recent behavior and execution history.",
    )


def _build_explanation(
    payload: dict[str, Any],
    evidence: ExplanationEvidence,
    provider: str,
    model_identifier: str,
) -> Explanation:
    """Normalize model output and attach evidence-derived grounded fields."""

    summary = str(
        payload.get("summary", "")
    ).strip()

    if not summary:
        raise ModelInferenceError(
            "model output did not contain a summary"
        )

    summary = _ensure_summary_names_app_and_severity(summary, evidence)

    normalized: dict[str, Any] = {"summary": summary}

    for field in _MODEL_LIST_FIELDS:
        normalized[field] = _clean_string_list(
            payload.get(field, []),
            _FIELD_LIMITS[field],
        )

    _reject_unsafe_text(
        [summary, *normalized["uncertainty"], *normalized["recommended_investigation"]]
    )

    if not normalized["recommended_investigation"]:
        normalized["recommended_investigation"] = [
            _default_investigation(evidence.severity)
        ]

    if not normalized["uncertainty"]:
        normalized["uncertainty"] = list(evidence.known_limitations)[:2]

    normalized.update(_evidence_derived_fields(evidence))

    if not normalized["what_changed"] or not normalized["why_unusual"]:
        raise ModelInferenceError(
            "no structured evidence was available to explain"
        )

    normalized["incident_id"] = evidence.incident_id
    normalized["generated_at"] = datetime.now(timezone.utc)
    normalized["provider"] = provider
    normalized["model_identifier"] = model_identifier
    normalized["generation_status"] = GenerationStatus.GENERATED

    try:
        return Explanation.model_validate(normalized)

    except Exception as error:
        raise ModelInferenceError(
            f"model output failed SignalTrace schema validation: {error}"
        ) from error