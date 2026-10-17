"""Every built-in detector: what it hides, what it keeps, and its label."""

from __future__ import annotations

import random

import pytest

from secretmask import MaskConfig, mask_text

from ._corpus import slack_webhook, tokens

LABEL = MaskConfig(strategy="label")


@pytest.mark.parametrize("seed", range(40))
def test_every_shape_is_hidden_and_labelled_by_its_detector(seed: int) -> None:
    for name, token in tokens(seed):
        text = f"value [{token}] end"
        assert mask_text(text, config=LABEL) == f"value [<redacted:{name}>] end", token


@pytest.mark.parametrize("seed", range(10))
def test_shapes_are_found_glued_to_quotes_and_punctuation(seed: int) -> None:
    for _, token in tokens(seed):
        for left, right in [('"', '"'), ("'", "',"), ("=", ";"), ("(", ")"), ("\n", "\n")]:
            assert token not in mask_text(f"x{left}{token}{right}y")


def test_slack_webhook_keeps_the_host_and_hides_the_path() -> None:
    url, secret = slack_webhook(random.Random(7))
    out = mask_text(f"post to {url} now", config=LABEL)
    assert out == "post to https://hooks.slack.com/services/<redacted:slack_webhook> now"
    assert secret not in out


@pytest.mark.parametrize(
    "text",
    [
        "risk-assessment-for-the-whole-project",  # "sk-" inside a word
        "disk_test_" + "a" * 20,  # "sk_test_" inside a word
        "pk_live_" + "a" * 24,  # Stripe publishable keys are public
        "XAKIA" + "B" * 16,  # glued to a letter
        "AKIA" + "B" * 17,  # one character too long
        "AIDA" + "B" * 16,  # an IAM user id, not a credential
        "AIza" + "b" * 34,  # one character short
        "ghp_" + "a" * 35,  # one character short
        "the bearer of bad news",
        "basic auth is basic",
        "count=3 and name=ada and max=9",
        "tokenizer=bert passwordless=true",
        "price 4111111111111111111111",  # 22 digits are not a card
        "ids 1 2 3 4 5 6 7 8 9 1 2 3 0",
        "2026-10-16 12:00:00,123",
        "café 你好 stays",
        "eyJhbGciOiJIUzI1NiJ9.only-two-segments",  # a JWT has at least three
        "sk-" + "a" * 19,  # one short of the 20 an sk- key needs
        "AIza" + "b" * 35 + "_prod",  # a longer word, not a key (as gitleaks reads it)
    ],
)
def test_lookalikes_are_left_alone(text: str) -> None:
    assert mask_text(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("postgres://admin:s3cr3t@db:5432/app", "postgres://admin:***@db:5432/app"),
        ("redis://:s3cr3t@cache:6379/0", "redis://:***@cache:6379/0"),
        ("https://u:p@ss@host/x@y", "https://u:***@host/x@y"),
        ("Server=db;Password=p4ss;Database=app", "Server=db;Password=***;Database=app"),
        ("Server=db;Pwd = {a;b c};Db=x", "Server=db;Pwd = ***;Db=x"),
        ('Password="two words";x', "Password=***;x"),
        ('Password="a;b";Db=x', "Password=***;Db=x"),
        ("Pwd={a;b};Db=x", "Pwd=***;Db=x"),
        ("Authorization: Basic QWxhZGRpbjpvcGVu", "Authorization: Basic ***"),
        ("authorization='basic QWxhZGRp'", "authorization='basic ***'"),
        ("Authorization: Bearer abc123def456ghi", "Authorization: Bearer ***"),
        ("AWS_SECRET_ACCESS_KEY=wJalrFAKEKEY", "AWS_SECRET_ACCESS_KEY=***"),
        ("client_secret: abcd", "client_secret: ***"),
        ('{"password": "hunter 2", "user": "ada"}', '{"password": "***", "user": "ada"}'),
        ("db.password = x", "db.password = ***"),
        ("password => abcdef", "password => ***"),
        ('{"client_secret": "it' + "'" + 's-Secret-99"}', '{"client_secret": "***"}'),
        ("api_key = 'O" + '"' + "Brien-Secret-99'", "api_key = '***'"),
        ('{"api_key": "ab' + "\\" + '"Secret-99"}', '{"api_key": "***"}'),
        (
            "postgres://admin:s3cr3t@db.example.com:5432/app",
            "postgres://admin:***@db.example.com:5432/app",
        ),
        ("amqp://u:p@ss@mq.example.org/vh", "amqp://u:***@mq.example.org/vh"),
        ("https://ada@example.org/x", "https://***/x"),
        ("https://acme.com,ada@example.org", "https://acme.com,***"),
        ("https://acme.com;ada@example.org", "https://acme.com;***"),
        ("https://acme.com|ada@example.org", "https://acme.com|***"),
        ("(https://acme.com)ada@example.org", "(https://acme.com)***"),
        ("'https://acme.com','ada@example.org'", "'https://acme.com','***'"),
        ("https://acme.com&to=ada@example.org", "https://acme.com&to=***"),
        ("https://acme.com ada@example.org", "https://acme.com ***"),
        ('["https://acme.com","ada@example.org"]', '["https://acme.com","***"]'),
        (
            "{'url':'https://acme.com','to':'ada@example.org'}",
            "{'url':'https://acme.com','to':'***'}",
        ),
        ("x https://h.com/a#b ada@b.io", "x https://h.com/a#b ***"),
        ('Password="pa"";re st";x', "Password=***;x"),
        ("Server=a;Password=a b c d;x", "Server=a;Password=***;x"),
        ("token=a'b'c", "token=***"),
        ('token=a"b', "token=***"),
        ("token=a''b", "token=***"),
        ("api_key: 'S3cr''etValue9'", "api_key: '***'"),
        ("{'password': 'it''s'}", "{'password': '***'}"),
        ('x = {"token": "a""b"}', 'x = {"token": "***"}'),
        ("Pwd='x'' y'", "Pwd=***"),
        ("Pwd={x}} y}", "Pwd=***"),
        ("token=" + "ab'" * 40 + "z", "token=***"),
        ("token=" + ("a" + "'" * 3 + "b") * 20, "token=***"),
        ("https://u:pw@h.com,ada@example.org", "https://u:***@h.com,***"),
        (
            "{'u':'https://u:pw@h.com','e':'ada@example.org'}",
            "{'u':'https://u:***@h.com','e':'***'}",
        ),
        ('["https://u:pw@h.com","ada@example.org"]', '["https://u:***@h.com","***"]'),
        ("<https://u:pw@h.com><ada@example.org>", "<https://u:***@h.com><***>"),
        ('"https://a.com","b:c@d@example.org"', '"https://a.com","b:c@***"'),
        ("token=https://u:pw@h.com/x", "token=***"),
        ("a" * 70 + "-bob@example.org", "***"),
        ("mailto:ada@example.org", "mailto:***"),
        ("Password=my Secret 99;Encrypt=True", "Password=***;Encrypt=True"),
        ("Password=my Secret 99 ;x", "Password=*** ;x"),
        ("Password=my" + chr(9) + "Secret;x", "Password=***;x"),
        ("Password=a b=c;x", "Password=*** b=c;x"),
        ("api_key = 'a" + chr(92) + "' tail Secret-99'", "api_key = '***'"),
        ('api_key = "ab' + "'cd'ef", 'api_key = "***'),
        ("https://u:a~b@host.example.com/", "https://u:***@host.example.com/"),
        ("https://u:a+b@host.example.com/", "https://u:***@host.example.com/"),
        ("ftp://ada:p!$&'()*+,;=709e@ftp.example.org/", "ftp://ada:***@ftp.example.org/"),
        ("see (ada@example.org)", "see (***)"),
        ('Password="pa""rest";x', "Password=***;x"),
        ("PWD={pa}}rest};x", "PWD=***;x"),
        ("password=abc user=bob", "password=*** user=bob"),
        ("PASSWORD=>'x y'", "PASSWORD=>'***'"),
        ("pwd => x", "pwd => ***"),
        ("password='x'", "password=***"),
        ("password=''", "password=***"),
        ("API-KEYS='k1,k2'", "API-KEYS='***'"),
        ("token=", "token="),
        ('token=""', 'token=""'),
        ("mail jane.doe+tag@mail.example.co.uk.", "mail ***."),
    ],
)
def test_partial_detectors_hide_only_the_secret(text: str, expected: str) -> None:
    assert mask_text(text) == expected


def test_tokens_after_a_hyphen_or_underscore_are_found() -> None:
    for token in ("ghp_" + "a" * 36, "sk-" + "a" * 20, "sk_live_" + "a" * 16):
        for left in ("x-", "x_", "-", "_"):
            assert mask_text(left + token) == left + "***", left + token


def test_escaped_connection_values_are_one_secret() -> None:
    config = MaskConfig(strategy="partial", keep_last=3)
    for value in ('"pa""rest"', "'pa''rest'", "{pa}}rest}"):
        expected = "*" * (len(value) - 3) + value[-3:]
        assert mask_text(f"Password={value};x", config=config) == f"Password={expected};x"


def test_more_documented_shapes() -> None:
    jwe = ".".join(["eyJhbGciOiJSU0EifQ", "a" * 20, "b" * 16, "c" * 30, "d" * 22])
    assert mask_text(f"[{jwe}]", config=LABEL) == "[<redacted:jwt>]"
    assert mask_text("whsec_" + "Ab+/=" * 6, config=LABEL) == "<redacted:stripe_key>"
    assert mask_text("ghs_1_" + tokens(3)[4][1], config=LABEL) == "<redacted:github_token>"
    assert mask_text("h-xoxb-123456789012-FAKE") == "h-***"
    for kept in ("a.xoxb-123456789012-FAKE", "7xoxb-123456789012-FAKE"):
        assert mask_text(kept) == kept
    for prefix in ("xoxe-1-", "xoxr-", "xoxe.xoxp-1-", "xoxa-2-"):
        assert mask_text(prefix + "FAKE" + "0" * 20, config=LABEL) == "<redacted:slack_token>"
    for kind in ("workflows", "triggers"):
        url = f"https://hooks.slack.com/{kind}/T0FAKE/A0FAKE/1234/abcdefghijklmnopqrst"
        assert mask_text(url, config=LABEL).endswith("/<redacted:slack_webhook>")
    pem = "-----BEGIN PRIVATE KEY-----\nMIIab----cdEF\n-----END PRIVATE KEY-----"
    assert mask_text(pem) == "***"


def test_a_known_shape_wins_over_the_generic_rules() -> None:
    jwt = tokens(1)[4][1]
    assert mask_text(f"Authorization: Bearer {jwt}", config=LABEL) == (
        "Authorization: Bearer <redacted:jwt>"
    )
    assert mask_text("api_key=AIza" + "c" * 35, config=LABEL) == (
        "api_key=<redacted:google_api_key>"
    )


def test_a_private_key_with_its_end_line_cut_off_is_still_hidden() -> None:
    text = "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nMIIEvQIBADANBg"
    assert mask_text(text) == "key: ***"
    two = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----BEGIN RSA PRIVATE KEY-----\nBBBB\n"
    assert mask_text(two, config=LABEL) == "<redacted:private_key>"  # touching: joined


def test_cards_are_whole_groups_and_keep_what_follows() -> None:
    assert mask_text("4111 1111 1111 1111 12/26") == "*** 12/26"
    assert mask_text("4111 1111 1111 1111 2026") == "*** 2026"
    assert mask_text("12 4111-1111-1111-1111 9") == "12 *** 9"
    assert mask_text("amex 3782 822463 10005.") == "amex ***."
    assert mask_text("4111 1111 1111 1112") == "4111 1111 1111 1112"
    assert mask_text("x4111111111111111y") == "x***y"


def test_other_scripts_digits_never_form_a_card() -> None:
    arabic = chr(0x0664) + chr(0x0661) * 15
    assert mask_text(f"num {arabic} ok") == f"num {arabic} ok"
