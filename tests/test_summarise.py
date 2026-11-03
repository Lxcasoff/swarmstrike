"""Having a model shorten output the compressor could not.

This talks to an OpenAI-compatible endpoint, so the tests run one in-process.
What they hold down is not the model's prose but the three rules around it:
the contract decides, credential material never leaves, and an endpoint that
misbehaves costs nothing.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from swarmstrike.engagement import OutputSummarisation
from swarmstrike.summarise import Summariser


class _Endpoint(BaseHTTPRequestHandler):
    reply: dict | None = {"choices": [{"message": {"content": "Three hosts, all 200."}}]}
    status = 200
    seen: list[dict] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        _Endpoint.seen.append({
            "path": self.path,
            "auth": self.headers.get("authorization"),
            "body": json.loads(self.rfile.read(length) or b"{}"),
        })
        self.send_response(_Endpoint.status)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_Endpoint.reply or {}).encode())

    def log_message(self, *_args):
        pass


@pytest.fixture
def endpoint():
    _Endpoint.seen = []
    _Endpoint.reply = {"choices": [{"message": {"content": "Three hosts, all 200."}}]}
    _Endpoint.status = 200
    server = HTTPServer(("127.0.0.1", 0), _Endpoint)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/v1"
    server.shutdown()


def _summariser(endpoint: str, **kwargs) -> Summariser:
    config = OutputSummarisation.model_construct(
        enabled=True, endpoint=endpoint, model="Qwen3_Coder-30B",
        max_input_chars=kwargs.pop("max_input_chars", 40_000), timeout_s=5,
    )
    return Summariser(config, api_key=kwargs.pop("api_key", "sk-test"))


# ---------------------------------------------------------------------------
#  The contract decides
# ---------------------------------------------------------------------------
def test_an_https_endpoint_is_required_when_enabled() -> None:
    """Scan output describes a client's unremediated weaknesses; it does not
    go out in the clear."""
    with pytest.raises(ValueError, match="https"):
        OutputSummarisation(enabled=True, endpoint="http://ai.example/v1", model="m")


def test_enabling_it_without_saying_where_is_refused() -> None:
    with pytest.raises(ValueError, match="endpoint and a model"):
        OutputSummarisation(enabled=True)


def test_nothing_is_sent_when_the_contract_is_silent(endpoint) -> None:
    quiet = Summariser(OutputSummarisation(), api_key="sk-test")
    assert quiet.summarise("anything at all") is None
    assert _Endpoint.seen == []


def test_nothing_is_sent_without_a_key(endpoint) -> None:
    assert _summariser(endpoint, api_key="").summarise("output") is None
    assert _Endpoint.seen == []


# ---------------------------------------------------------------------------
#  Credential material never leaves
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    '{"email":"a@b.c","password":"9283f1b2e9669749081963be0462e466"}',
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n",
    "set-cookie: t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u",
])
def test_credential_material_is_never_sent(endpoint, payload) -> None:
    """An endpoint that is fine for a directory listing is not a place to post
    a client's password store."""
    assert _summariser(endpoint).summarise(payload) is None
    assert _Endpoint.seen == []


def test_ordinary_output_is_sent(endpoint) -> None:
    result = _summariser(endpoint).summarise(
        "10.0.0.1 200\n10.0.0.2 404\n", context="httpx -u 10.0.0.0/24")

    assert result is not None and result.text == "Three hosts, all 200."
    assert len(_Endpoint.seen) == 1
    sent = _Endpoint.seen[0]
    assert sent["path"].endswith("/v1/chat/completions")
    assert sent["auth"] == "Bearer sk-test"
    assert sent["body"]["model"] == "Qwen3_Coder-30B"
    # The command goes with the output, so the model knows what produced it.
    assert "httpx -u 10.0.0.0/24" in sent["body"]["messages"][1]["content"]


def test_oversized_output_is_cut_before_it_is_sent(endpoint) -> None:
    """A summariser asked for a verdict on a megabyte answers worse and costs
    more."""
    _summariser(endpoint, max_input_chars=500).summarise("x" * 50_000)
    assert len(_Endpoint.seen[0]["body"]["messages"][1]["content"]) < 1_200


# ---------------------------------------------------------------------------
#  A failing endpoint costs nothing
# ---------------------------------------------------------------------------
def test_a_server_error_gives_nothing_back(endpoint) -> None:
    _Endpoint.status = 500
    assert _summariser(endpoint).summarise("output") is None


def test_an_unparseable_reply_gives_nothing_back(endpoint) -> None:
    _Endpoint.reply = {"unexpected": "shape"}
    assert _summariser(endpoint).summarise("output") is None


def test_an_endpoint_that_is_not_there_gives_nothing_back() -> None:
    """Summarisation improves a result that already exists. It is never a
    dependency, so a campaign does not fail when it is unreachable."""
    nowhere = _summariser("https://127.0.0.1:1/v1")
    assert nowhere.summarise("output") is None


# ---------------------------------------------------------------------------
#  Wired into the executor
# ---------------------------------------------------------------------------
def test_the_executor_runs_it_and_says_whose_account_it_is(endpoint, tmp_path) -> None:
    """The feature existed for a while without being connected to anything.
    This is the test that would have caught that."""
    import asyncio

    from swarmstrike.tools.executor import ToolExecutor

    executor = ToolExecutor.__new__(ToolExecutor)
    executor.summariser = _summariser(endpoint)
    executor.summariser.config.min_chars = 10
    executor._emit = lambda *a, **k: None

    out = asyncio.run(executor._maybe_summarise(
        "x" * 4000, "nuclei -u https://app.test", tmp_path / "0007.txt"))

    assert "Three hosts, all 200." in out
    # An agent must know when it is reading a model's account rather than the
    # tool's own output, or a finding rests on a paraphrase unknowingly.
    assert "not the tool's output" in out
    assert "0007.txt" in out
    assert len(_Endpoint.seen) == 1


def test_short_output_is_not_worth_a_round_trip(endpoint, tmp_path) -> None:
    import asyncio

    from swarmstrike.tools.executor import ToolExecutor

    executor = ToolExecutor.__new__(ToolExecutor)
    executor.summariser = _summariser(endpoint)
    executor.summariser.config.min_chars = 4_000
    executor._emit = lambda *a, **k: None

    text = "200 OK\n"
    assert asyncio.run(executor._maybe_summarise(text, "curl", tmp_path / "x.txt")) == text
    assert _Endpoint.seen == []


def test_without_a_summariser_the_output_passes_through(tmp_path) -> None:
    import asyncio

    from swarmstrike.tools.executor import ToolExecutor

    executor = ToolExecutor.__new__(ToolExecutor)
    executor.summariser = None
    text = "y" * 90_000
    assert asyncio.run(executor._maybe_summarise(text, "curl", tmp_path / "x.txt")) == text
