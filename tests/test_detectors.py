"""The detectors added this round, plus Unicode and backtracking safety."""

from __future__ import annotations

import time

from secretmask import mask_text


def test_redacts_a_pem_private_key_block() -> None:
    pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIabc\nnopqrs==\n-----END EC PRIVATE KEY-----"
    out = mask_text(f"key:\n{pem}\ndone")
    assert "MHcCAQEEIabc" not in out
    assert out.startswith("key:")
    assert out.endswith("done")


def test_hides_only_the_password_inside_a_url() -> None:
    out = mask_text("conn postgres://admin:s3cr3tpw@db.host:5432/app")
    assert "s3cr3tpw" not in out
    assert "postgres://admin:" in out
    assert "@db.host:5432/app" in out


def test_hides_the_value_of_a_connection_string_password() -> None:
    out = mask_text("Server=db;Password=p4ssw0rd;Database=app")
    assert "p4ssw0rd" not in out
    assert "Server=db;" in out
    assert "Database=app" in out


def test_hides_a_generic_key_value_assignment() -> None:
    out = mask_text("loaded api_key=AbCd1234EfGh5678 and token: ZZtopSecret99")
    assert "AbCd1234EfGh5678" not in out
    assert "ZZtopSecret99" not in out
    assert "loaded api_key=" in out


def test_leaves_a_non_secret_assignment_alone() -> None:
    assert mask_text("count=3 and name=ada") == "count=3 and name=ada"


def test_unicode_text_round_trips_untouched() -> None:
    arabic_digits = "".join(chr(0x0660 + n) for n in range(10))
    text = f"café 你好 stays, {arabic_digits} digits stay"
    assert mask_text(text) == text


def test_unicode_digits_are_not_treated_as_a_card() -> None:
    # Arabic-Indic digits that would be a valid card length must not be masked.
    arabic = chr(0x0664) + chr(0x0661) * 15
    assert mask_text(f"num {arabic} ok") == f"num {arabic} ok"


def test_adjacent_secrets_are_both_masked() -> None:
    out = mask_text("a@b.io c@d.io")
    assert "a@b.io" not in out
    assert "c@d.io" not in out


def test_no_catastrophic_backtracking_on_pathological_input() -> None:
    # A long run that teases the url, bearer and assignment rules. Linear regexes
    # finish this in milliseconds; a backtracking one would hang.
    pathological = "Bearer " + "a" * 20000 + " " + "x=" + "y" * 20000 + " " + ":" * 20000
    start = time.perf_counter()
    mask_text(pathological)
    assert time.perf_counter() - start < 2.0
