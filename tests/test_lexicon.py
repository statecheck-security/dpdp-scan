import pytest

from dpdp_scan.detectors.base import Step
from dpdp_scan.model import Category
from dpdp_scan.schema.lexicon import classify_name, provisions_for, tokens


@pytest.mark.parametrize(
    ("name", "toks"),
    [
        ("aadhaarNo", ("aadhaar", "no")),
        ("DATE_OF_BIRTH", ("date", "of", "birth")),
        ("customer-email-address", ("customer", "email", "address")),
        ("phone2", ("phone",)),
        ("IPAddress", ("ip", "address")),
        ("mobNo", ("mob", "no")),
        ("", ()),
    ],
)
def test_tokens(name: str, toks: tuple[str, ...]) -> None:
    assert tokens(name) == toks


@pytest.mark.parametrize(
    ("name", "category", "step"),
    [
        # Indian identifiers, abbreviations and misspellings
        ("aadhaar_number", Category.IDENTITY, Step.HIGH),
        ("aadhar_no", Category.IDENTITY, Step.HIGH),
        ("custAdhaar", Category.IDENTITY, Step.HIGH),
        ("pan_no", Category.IDENTITY, Step.HIGH),
        ("pan", Category.IDENTITY, Step.MEDIUM),
        ("passportNumber", Category.IDENTITY, Step.HIGH),
        ("voter_id", Category.IDENTITY, Step.HIGH),
        ("dl_no", Category.IDENTITY, Step.HIGH),
        ("father_name", Category.IDENTITY, Step.HIGH),
        ("fathername", Category.IDENTITY, Step.HIGH),
        ("firstName", Category.IDENTITY, Step.MEDIUM),
        ("username", Category.IDENTITY, Step.LOW),
        ("avatarUrl", Category.IDENTITY, Step.LOW),
        # Contact
        ("email", Category.CONTACT, Step.HIGH),
        ("emailId", Category.CONTACT, Step.HIGH),
        ("mobno", Category.CONTACT, Step.HIGH),
        ("mob_no", Category.CONTACT, Step.HIGH),
        ("whatsapp_number", Category.CONTACT, Step.HIGH),
        ("address_line_1", Category.CONTACT, Step.MEDIUM),
        ("pincode", Category.CONTACT, Step.MEDIUM),
        ("pin_code", Category.CONTACT, Step.MEDIUM),
        # Financial
        ("ifsc_code", Category.FINANCIAL, Step.HIGH),
        ("upi_id", Category.FINANCIAL, Step.HIGH),
        ("gstin", Category.FINANCIAL, Step.HIGH),
        ("bank_account_no", Category.FINANCIAL, Step.HIGH),
        ("walletAddress", Category.FINANCIAL, Step.LOW),
        ("uan", Category.FINANCIAL, Step.HIGH),
        # Health, biometric, location, age
        ("abha_id", Category.HEALTH, Step.HIGH),
        ("blood_group", Category.HEALTH, Step.HIGH),
        ("fingerprint_template", Category.BIOMETRIC, Step.HIGH),
        ("latitude", Category.LOCATION, Step.MEDIUM),
        ("dob", Category.AGE_DOB, Step.HIGH),
        ("dateOfBirth", Category.AGE_DOB, Step.HIGH),
        ("is_minor", Category.AGE_DOB, Step.MEDIUM),
        ("age", Category.AGE_DOB, Step.MEDIUM),
        # Other
        ("gender", Category.OTHER, Step.MEDIUM),
        ("caste", Category.OTHER, Step.HIGH),
        ("ip_address", Category.OTHER, Step.MEDIUM),
        ("device_fingerprint", Category.OTHER, Step.MEDIUM),
    ],
)
def test_classify_positive(name: str, category: Category, step: Step) -> None:
    cls = classify_name(name)
    assert cls is not None, name
    assert (cls.category, cls.step) == (category, step)


@pytest.mark.parametrize(
    "name",
    [
        "id",
        "created_at",
        "updatedAt",
        "tokenHash",
        "createTxHash",
        "contract_address",
        "password_hash",
        "company_name",
        "product_name",
        "game_name",
        "session_id",
        "status",
        "amount",
        "description",
        "slug",
        "coverImage",
        "minWager",
        "legal_basis",
        "canonical_hash",
        "language_code",
        "panel_id",  # "panel" is not "pan"
        "spanish",
        "adobe_key",  # "adobe" is not "dob"
    ],
)
def test_classify_negative(name: str) -> None:
    assert classify_name(name) is None, name


@pytest.mark.parametrize(
    ("container", "expected"),
    [("users", True), ("User", True), ("kyc_records", True), ("public.customers", True)],
)
def test_bare_name_is_personal_only_in_a_person_container(container: str, expected: bool) -> None:
    assert (classify_name("name", container) is not None) is expected


@pytest.mark.parametrize("container", ["games", "Game", "products", "BlockchainEvent", ""])
def test_bare_name_outside_person_containers_is_nothing(container: str) -> None:
    assert classify_name("name", container) is None
    assert classify_name("eventName", container) is None


def test_age_dob_adds_section_9() -> None:
    refs = [p.ref for p in provisions_for(Category.AGE_DOB)]
    assert refs[0] == "S.9" and "S.8(5)" in refs
    assert [p.ref for p in provisions_for(Category.CONTACT)] == ["S.8(5)", "Rule 6(1)(a)"]
