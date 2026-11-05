import pytest

from fde_pii_redaction import detectors
from fde_pii_redaction.detectors import (
    detect_all,
    detect_cards,
    detect_emails,
    detect_ibans,
    detect_long_numbers,
    detect_names,
    detect_phones,
    detect_ssns,
    iban_ok,
    luhn_ok,
    ssn_ok,
)


# ------------------------------------------------------------------ email

def test_email_detected():
    spans = detect_emails("write to fixture@example.com today")
    assert [s.value for s in spans] == ["fixture@example.com"]


def test_email_not_flagged_without_tld():
    assert detect_emails("the host is example dot com") == []


# ------------------------------------------------------------------ cards

@pytest.mark.parametrize("digits", ["4111111111111111", "5555555555554444"])
def test_luhn_accepts_test_cards(digits):
    assert luhn_ok(digits)


@pytest.mark.parametrize(
    "digits", ["1234567890123456", "4111111111111112", "9999999999999999"]
)
def test_luhn_rejects_random_numbers(digits):
    assert not luhn_ok(digits)


def test_card_detector_flags_spaced_and_dashed():
    text = "a 4111-1111-1111-1111 b 5555 5555 5555 4444 c"
    assert len(detect_cards(text)) == 2


def test_card_detector_skips_non_luhn_16_digit_string():
    # Random 16-digit strings that fail Luhn must NOT flag as cards.
    assert detect_cards("reference 1234 5678 9012 3456 logged") == []
    assert detect_cards("reference 1234567890123456 logged") == []


# ------------------------------------------------------------------- iban

@pytest.mark.parametrize(
    "iban", ["GB29NWBK60161331926819", "DE89370400440532013000"]
)
def test_iban_mod97_accepts_valid(iban):
    assert iban_ok(iban)


@pytest.mark.parametrize(
    "iban", ["GB29NWBK60161331926818", "DE89370400440532013001"]
)
def test_iban_mod97_rejects_invalid(iban):
    assert not iban_ok(iban)


def test_iban_detector_ignores_bad_checksum():
    assert detect_ibans("pay GB29 NWBK 6016 1331 9268 18 now") == []
    spans = detect_ibans("pay GB29 NWBK 6016 1331 9268 19 now")
    assert len(spans) == 1 and spans[0].type == "IBAN"


# -------------------------------------------------------------------- ssn

def test_ssn_valid_fixture():
    assert ssn_ok("123", "45", "6789")
    assert [s.value for s in detect_ssns("ssn 123-45-6789 on file")] == [
        "123-45-6789"
    ]


@pytest.mark.parametrize(
    "bad", ["000-45-6789", "666-45-6789", "900-45-6789", "987-45-6789",
            "123-00-6789", "123-45-0000"]
)
def test_ssn_validity_rules_reject(bad):
    assert detect_ssns(f"number {bad} here") == []


# ------------------------------------------------------------------ phone

@pytest.mark.parametrize(
    "phone", ["(212) 555-0147", "+1 212-555-0147", "212-555-0147",
              "+44 20 7946 0958", "+1-555-0147"]
)
def test_phone_formats(phone):
    spans = detect_phones(f"call {phone} now")
    assert any(s.value == phone for s in spans)


def test_phone_detector_ignores_dates():
    assert detect_phones("released 2026-11-05 in version 2") == []


# ------------------------------------------------------------------ names

def test_name_from_fixture_dictionary():
    spans = detect_names("the customer Alice Johnson called")
    assert [s.value for s in spans] == ["Alice Johnson"]


def test_name_from_title_pattern():
    spans = detect_names("referred by Dr. Frank Miller")
    assert any("Frank Miller" in s.value for s in spans)


def test_name_from_context_pattern():
    spans = detect_names("Name: Grace Wilson")
    assert [s.value for s in spans] == ["Grace Wilson"]


def test_unknown_name_not_flagged():
    assert detect_names("the customer Zebediah Quirks called") == []


# ------------------------------------------------------------------- misc

def test_address_pattern():
    spans = detect_all("ship to 123 Main Street, Springfield, IL 62701 today")
    assert [s.type for s in spans] == ["ADDRESS"]


def test_long_number_guard_needs_label_and_length():
    spans = detect_long_numbers("Passport ID: 123456789012 recorded")
    assert len(spans) == 1 and spans[0].type == "ID"
    # No label -> not flagged, even at the same length.
    assert detect_long_numbers("the count was 123456789012 units") == []
    # Labelled but below the 12-digit threshold -> untouched.
    assert detect_long_numbers("Invoice ID: 12345678 paid") == []


# ------------------------------------------------------- overlap handling

def test_overlap_card_wins_over_phone_substring():
    spans = detect_all("card 4111-1111-1111-1111 end")
    assert len(spans) == 1 and spans[0].type == "CARD"


def test_overlap_iban_wins_over_card_substring():
    spans = detect_all("iban GB29 NWBK 6016 1331 9268 19 end")
    assert len(spans) == 1 and spans[0].type == "IBAN"


def test_overlap_name_inside_address_resolves_to_one_span():
    text = "office at 742 Alice Johnson Road"
    spans = detect_all(text)
    assert len(spans) == 1 and spans[0].type == "ADDRESS"


def test_resolve_overlaps_keeps_disjoint_spans():
    spans = detect_all("mail fixture@example.com or call (212) 555-0147")
    assert [s.type for s in spans] == ["EMAIL", "PHONE"]
