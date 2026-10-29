"""Credential material a target returned, and what the campaign does about it.

`redact` covers the other direction — secrets swarmstrike sends, which a recipe
declared. Nothing covered what a target returns, and the first live campaign
wrote a user table with password hashes into the output directory in the clear.
The output is deliberately left intact: the proof of an exposure is what was
exposed. What these tests pin down is that nobody ends up holding it unaware.
"""

from __future__ import annotations

import json

import pytest

from swarmstrike.sensitive import MANIFEST_NAME, classify, mark, read_manifest


@pytest.mark.parametrize(
    ("label", "text", "expected"),
    [
        (
            "the juice shop user row that halted the first campaign",
            '{"email":"bjoern@owasp.org","password":"9283f1b2e9669749081963be0462e466"}',
            ("password hash",),
        ),
        ("bcrypt", '{"password":"$2b$12$abcdefghijklmnopqrstuv"}', ("password hash",)),
        ("shadow line", "svc:$6$salt$abcdefghijklmnopqrstuvwxyz0123456789", ("password hash",)),
        ("cleartext", '{"username":"svc","password":"Hunter2!summer"}', ("cleartext password",)),
        ("private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", ("private key",)),
        (
            "jwt",
            "set-cookie: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u",
            ("session token or JWT",),
        ),
        ("aws key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", ("API key",)),
    ],
)
def test_credential_material_is_recognised(label, text, expected) -> None:
    assert classify(text) == expected, label


@pytest.mark.parametrize(
    ("label", "text"),
    [
        # A bare 32-hex string is as likely to be a request id as an MD5 hash,
        # so the hash patterns only fire next to a credential-ish key.
        ("a request id", '{"requestId":"9283f1b2e9669749081963be0462e466"}'),
        ("an empty field", '{"password":""}'),
        ("an ordinary page", "<html><body>Products</body></html>"),
        ("a git commit", "commit 3d12037a9f1c4e2b8a7d6f5e4c3b2a1908f7e6d5"),
    ],
)
def test_ordinary_output_is_not_flagged(label, text) -> None:
    """A manifest that cries wolf is a manifest nobody reads."""
    assert classify(text) == (), label


def test_a_hashed_password_is_not_reported_as_cleartext() -> None:
    """Both patterns can match the same field, and "hashed store exposed in
    cleartext" is a different and wronger finding than the real one."""
    kinds = classify('{"password":"9283f1b2e9669749081963be0462e466"}')
    assert "cleartext password" not in kinds


def test_marking_records_the_file_without_touching_it(tmp_path) -> None:
    body = '$ curl http://x/api/Users\n{"password":"$2b$12$abcdefghijklmnopqrstuv"}'
    evidence = tmp_path / "0045-api-curl.txt"
    evidence.write_text(body)

    marking = mark(tmp_path, evidence.name, body)

    assert marking is not None
    assert marking.kinds == ("password hash",)
    # The evidence is the proof of the exposure. It is not altered.
    assert evidence.read_text() == body

    manifest = json.loads((tmp_path / MANIFEST_NAME).read_text())
    assert manifest == {"0045-api-curl.txt": ["password hash"]}


def test_clean_output_leaves_no_manifest(tmp_path) -> None:
    assert mark(tmp_path, "0001-web-curl.txt", "<html>nothing here</html>") is None
    assert not (tmp_path / MANIFEST_NAME).exists()
    assert read_manifest(tmp_path) == []


def test_remarking_a_file_does_not_duplicate_it(tmp_path) -> None:
    """A resumed campaign re-runs commands; the manifest is an inventory, not a log."""
    body = "-----BEGIN RSA PRIVATE KEY-----"
    for _ in range(3):
        mark(tmp_path, "0007-web-curl.txt", body)
    mark(tmp_path, "0008-api-curl.txt", '{"password":"Hunter2!summer"}')

    marked = read_manifest(tmp_path)
    assert [m.path for m in marked] == ["0007-web-curl.txt", "0008-api-curl.txt"]


def test_an_unreadable_manifest_does_not_take_the_report_down(tmp_path) -> None:
    (tmp_path / MANIFEST_NAME).write_text("{ this is not json")
    assert read_manifest(tmp_path) == []
    # And a later marking repairs it rather than failing.
    assert mark(tmp_path, "0001-api-curl.txt", '{"password":"Hunter2!x"}') is not None
    assert [m.path for m in read_manifest(tmp_path)] == ["0001-api-curl.txt"]
