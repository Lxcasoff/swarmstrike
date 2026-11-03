"""Asking a model to shorten output the compressor could not.

`compress` handles the shapes our recipes produce and needs no network. Some
output has no shape it knows — an HTML page, a format nobody wrote a strategy
for — and that is what this is for.

It is a different kind of decision from compression, because the output leaves
the machine. A client's scan results describe their unremediated weaknesses,
so three things hold:

* **The contract decides.** Off unless the signed engagement turns it on, and
  the endpoint is named in the contract rather than read from the environment,
  so the signature covers where the data goes.
* **Credential material never leaves.** If the output holds a password hash, a
  private key or a token, nothing is sent and the deterministic result stands.
  An endpoint that is fine for a directory listing is not a place to post a
  client's password store.
* **Failure is silent and safe.** An endpoint that is down, slow or wrong
  gives nothing back, and the caller keeps what it already had. Summarisation
  is an improvement on a result that already exists, never a dependency.

Any OpenAI-compatible `/v1/chat/completions` serves. It speaks over urllib
rather than adding a client library, because one HTTP call does not justify a
dependency in a tool that touches client systems.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import sensitive
from .engagement import OutputSummarisation

SYSTEM_PROMPT = (
    "You condense the output of a security assessment tool for another "
    "assessor who will act on it. Report what the output shows: hosts, "
    "endpoints, status codes, versions, errors, anything anomalous. Keep "
    "every identifier, path, version string and status code exactly as "
    "written — they are evidence and will be quoted in a report. Do not "
    "speculate about vulnerabilities, do not recommend actions, and do not "
    "invent anything the output does not contain. If the output shows "
    "nothing of interest, say so in one line."
)


@dataclass
class Summary:
    text: str
    model: str
    input_chars: int


class Summariser:
    """A model that shortens tool output, when the contract allows one."""

    def __init__(self, config: OutputSummarisation, api_key: str = "") -> None:
        self.config = config
        self.api_key = api_key

    @property
    def available(self) -> bool:
        return bool(self.config.enabled and self.config.endpoint
                    and self.config.model and self.api_key)

    def why_unavailable(self) -> str:
        if not self.config.enabled:
            return "the engagement contract does not authorize output summarisation"
        if not self.config.endpoint or not self.config.model:
            return "the contract authorizes summarisation but names no endpoint or model"
        if not self.api_key:
            return "no API key for the summarisation endpoint (SWARMSTRIKE_SUMMARISER_KEY)"
        return ""

    def summarise(self, text: str, *, context: str = "") -> Summary | None:
        """A shorter account of `text`, or None if it cannot or must not be made."""
        if not self.available:
            return None

        # The interlock. Everything else here is about usefulness; this is the
        # one check that is about not leaking a client's credentials to a
        # third party because an agent happened to read a user table.
        kinds = sensitive.classify(text)
        if kinds:
            return None

        body = text[: self.config.max_input_chars]
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Command: {context}\n\nOutput:\n{body}" if context
                    else f"Output:\n{body}")},
            ],
            "temperature": 0,
            "max_tokens": 700,
        }

        url = self.config.endpoint.rstrip("/") + "/chat/completions"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_s) as response:
                answer = json.load(response)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            # A summariser that is down is not a campaign that fails.
            return None

        try:
            content = answer["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError, AttributeError):
            return None
        if not content:
            return None
        return Summary(content, self.config.model, len(body))
