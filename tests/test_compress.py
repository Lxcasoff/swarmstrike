"""Shrinking what an agent reads.

The executor used to hand an agent the first 60,000 characters of a tool's
output. For a scanner that is a cut by position, and a scanner's findings are
usually at the end: the lab's largest evidence file is 2.2 MB, of which the
agent saw the opening 2.7% — all of it response bodies, none of it results.

What these tests hold down is that the compressor keeps the signal, says what
it removed, and never touches the record on disk.
"""

from __future__ import annotations

import json

from swarmstrike.compress import compress

LIMIT = 2_000


def test_output_within_the_budget_is_untouched() -> None:
    text = "HTTP/1.1 200 OK\nServer: nginx\n\nhello"
    result = compress(text, limit=LIMIT)
    assert result.text == text
    assert result.strategy == "none"
    assert result.render("/tmp/x.txt") == text


def test_a_curl_loop_keeps_its_results_and_drops_the_bodies() -> None:
    """The shape of the lab's two largest files: a result line per URL, with
    kilobytes of HTML between them."""
    body = "<html><body>" + ("x" * 3000) + "</body></html>"
    lines = []
    for index in range(40):
        lines.append(body)
        lines.append(f"http://10.0.0.1:3000/api/item{index} 200 application/json 412")
    text = "$ curl -s -w '%{url_effective} %{http_code}'\n" + "\n".join(lines)

    result = compress(text, limit=LIMIT)

    assert result.strategy == "http-metrics"
    assert result.kept_chars < len(text) / 50
    # Results from both ends survive: a cut by position loses one or the other.
    assert "item0 200" in result.text
    assert "item39 200" in result.text
    assert "<html>" not in result.text
    assert any("dropped the response bodies" in note for note in result.notes)


def test_a_status_code_must_be_adjacent_to_its_url() -> None:
    """A documentation link quoted inside a JSON body is not a scan result.
    Matching a code anywhere nearby showed the agent cheat-sheet URLs as if
    they were findings."""
    noise = ('{"mitigationUrl":"https://cheatsheetseries.owasp.org/x.html",'
             '"difficulty":3,"order":200,"solved":false}')
    text = "\n".join([noise] * 60)
    result = compress(text, limit=LIMIT)
    # These are JSON records, and reading them as records is right. What must
    # not happen is reading the quoted link as a scan result.
    assert result.strategy != "http-metrics"


def test_json_lines_lose_their_request_and_response_bodies() -> None:
    records = [
        json.dumps({
            "template-id": f"cve-2026-{n}", "host": "https://app.test",
            "info": {"severity": "high", "name": f"Finding {n}"},
            "matched-at": f"https://app.test/{n}",
            "request": "GET / HTTP/1.1\n" + "A" * 2000,
            "response": "HTTP/1.1 200 OK\n" + "B" * 2000,
        })
        for n in range(30)
    ]
    result = compress("\n".join(records), limit=LIMIT)

    assert result.strategy == "json-lines"
    assert "AAAA" not in result.text and "BBBB" not in result.text
    assert "cve-2026-0" in result.text
    assert "severity=high" in result.text
    assert any("request and response" in note for note in result.notes)


def test_a_single_response_keeps_its_headers() -> None:
    text = ("HTTP/1.1 500 Internal Server Error\nServer: Apache/2.4.25\n"
            "X-Powered-By: PHP/7.0.30\n\n" + "<html>" + "z" * 50_000 + "</html>")
    result = compress(text, limit=LIMIT)

    assert result.strategy == "http-response"
    # The headers are the finding; the body is evidence already on disk.
    assert "500 Internal Server Error" in result.text
    assert "Apache/2.4.25" in result.text
    assert "PHP/7.0.30" in result.text
    assert result.kept_chars < len(text) / 10


def test_repeated_lines_collapse() -> None:
    text = "\n".join(["connection refused"] * 4000)
    result = compress(text, limit=LIMIT)
    assert result.text.count("connection refused") == 1
    assert any("repeated line" in note for note in result.notes)


def test_the_account_names_what_went_and_where_the_original_is() -> None:
    text = "\n".join(f"line {n} {'y' * 200}" for n in range(500))
    rendered = compress(text, limit=LIMIT).render("campaigns/C/output/0007.txt")

    assert "campaigns/C/output/0007.txt" in rendered
    assert "% less" in rendered
    # Never "100% less", which reads as a claim that nothing was kept.
    assert "100.0% less" not in rendered


def test_binary_output_does_not_poison_the_result_lines() -> None:
    text = "\n".join(
        f"�\x00\x01binary{n}\x02 http://10.0.0.1/video{n} 200 video/mp4 2232676"
        for n in range(40)
    )
    result = compress(text, limit=LIMIT)
    assert "�" not in result.text
    assert "\x00" not in result.text
