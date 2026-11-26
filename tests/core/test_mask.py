import pytest

from lynx.core.mask import mask_secrets

# Fake secrets are assembled from parts so this file never contains a literal token
# that secret scanners (GitHub push protection, gitleaks) would flag.
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GITHUB_TOKEN = "ghp" + "_" + "a1B2c3D4" * 5
GITHUB_PAT = "github" + "_pat_" + "11ABCDEFG0" + "x" * 30
SLACK_TOKEN = "xox" + "b-" + "1234567890-" + "abcdefghij"
GOOGLE_KEY = "AIza" + "Sy" + "A" * 33
STRIPE_KEY = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
ANTHROPIC_KEY = "sk" + "-ant-" + "api03-" + "x" * 30
OPENAI_KEY = "sk" + "-proj-" + "y" * 40
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0In0" + ".abc123XYZ_-signature"
PRIVATE_KEY = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\nMIIEow"
    + "IBAAKCAQEA\n-----END "
    + "RSA PRIVATE KEY-----"
)


def _mask(text: str) -> str:
    masked: str = mask_secrets({"text": text})["text"]
    return masked


@pytest.mark.parametrize(
    ("secret", "kind"),
    [
        (AWS_KEY, "AWS_ACCESS_KEY"),
        (GITHUB_TOKEN, "GITHUB_TOKEN"),
        (GITHUB_PAT, "GITHUB_TOKEN"),
        (SLACK_TOKEN, "SLACK_TOKEN"),
        (GOOGLE_KEY, "GOOGLE_API_KEY"),
        (STRIPE_KEY, "STRIPE_KEY"),
        (ANTHROPIC_KEY, "ANTHROPIC_KEY"),
        (OPENAI_KEY, "OPENAI_KEY"),
        (JWT, "JWT"),
        (PRIVATE_KEY, "PRIVATE_KEY"),
    ],
)
def test_known_token_formats_are_redacted(secret: str, kind: str) -> None:
    masked = _mask(f"found {secret} in config")

    assert secret not in masked
    assert masked == f"found [REDACTED:{kind}] in config"


@pytest.mark.parametrize(
    "header",
    [
        "Authorization: Bearer abc.def-ghi_123",
        "authorization=Basic dXNlcjpwYXNzd29yZA==",
        "Authorization: token 0123456789abcdef",
    ],
)
def test_authorization_values_are_redacted_but_the_header_stays(header: str) -> None:
    masked = _mask(header)

    assert header.split()[-1] not in masked
    assert masked.lower().startswith("authorization")
    assert masked.endswith("[REDACTED:AUTHORIZATION]")


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("password = 'hunter22'", "hunter22"),
        ('"api_key": "k3y-v4lue-123"', "k3y-v4lue-123"),
        ("CLIENT_SECRET=abcdef123456", "abcdef123456"),
        ("access_token: zzzz9999", "zzzz9999"),
    ],
)
def test_secret_assignments_keep_the_name_and_hide_the_value(text: str, value: str) -> None:
    masked = _mask(text)

    assert value not in masked
    assert "[REDACTED:SECRET]" in masked


def test_credentials_in_urls_are_redacted() -> None:
    masked = _mask("connect to https://admin:s3cr3t-pass@db.example.test/app")

    assert "s3cr3t-pass" not in masked
    assert "admin" not in masked
    assert masked == "connect to https://[REDACTED:URL_CREDENTIALS]@db.example.test/app"


def test_secret_query_values_are_redacted_and_other_parameters_kept() -> None:
    masked = _mask("https://app.test/cb?code=1&api_key=abcd1234&x=2")

    assert "abcd1234" not in masked
    assert masked == "https://app.test/cb?code=1&api_key=[REDACTED:SECRET]&x=2"


@pytest.mark.parametrize(
    "text",
    [
        "SQL injection in the search endpoint",
        "The password field accepts empty values",
        "Hard-coded secret in settings.py",
        "CWE-89",
        "app/db.py",
        "https://app.test/items?id=42",
        "uses sk-learn for scoring",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert _mask(text) == text


def test_nested_strings_are_masked_and_other_values_kept() -> None:
    document = {"runs": [{"message": {"text": f"key {AWS_KEY}"}, "count": 3, "ok": True}]}

    masked = mask_secrets(document)

    assert masked == {
        "runs": [{"message": {"text": "key [REDACTED:AWS_ACCESS_KEY]"}, "count": 3, "ok": True}]
    }


def test_the_input_document_is_not_modified() -> None:
    document = {"text": AWS_KEY}

    mask_secrets(document)

    assert document == {"text": AWS_KEY}
