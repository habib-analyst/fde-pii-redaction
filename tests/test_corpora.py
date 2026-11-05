"""Precision / recall discipline over the fixture corpora.

Recall: every planted PII item in the PII corpus is caught.
Precision: every string in the clean corpus passes through unchanged.
"""

from fde_pii_redaction import RedactionEngine
from fde_pii_redaction.fixtures import CLEAN_CORPUS, PII_CORPUS_TEXT, PII_PLANTED


def test_pii_corpus_full_recall():
    engine = RedactionEngine()
    result = engine.redact_text(PII_CORPUS_TEXT)
    for value, pii_type in PII_PLANTED:
        assert value not in result.output, f"{pii_type} value leaked: {value}"
        assert result.counts.get(pii_type, 0) >= 1, f"no {pii_type} count"


def test_clean_corpus_zero_changes():
    engine = RedactionEngine()
    for text in CLEAN_CORPUS:
        result = engine.redact_text(text)
        assert result.output == text, f"clean text was changed: {text}"
        assert result.counts == {}


def test_clean_corpus_zero_changes_json_mode():
    engine = RedactionEngine()
    payload = {"lines": list(CLEAN_CORPUS), "n": len(CLEAN_CORPUS)}
    result = engine.redact_json(payload)
    assert result.output == payload
