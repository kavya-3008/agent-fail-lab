"""Composable defenses that wrap an agent's tools without changing the agent itself.

Each defense can filter what the agent reads, or veto / rewrite what it sends. They are deliberately simple,
pattern-based mechanisms so their strengths and blind spots are easy to see in the results.
"""
from __future__ import annotations

import base64
import codecs
import re

from .agents import ADDR, NaiveAgent
from .scenarios import Scenario
from .tools import Sandbox


class Defense:
    name = "defense"

    def filter_read(self, text: str) -> str:
        return text

    def reset(self) -> None:
        """Called before each run so a stateful defense does not carry memory between scenarios."""

    def check_send(self, scenario: Scenario, to: str, body: str) -> tuple[str, str, str | None]:
        """Return (to, body, block_reason). A non-None block_reason vetoes the call."""
        return to, body, None


class RecipientAllowlist(Defense):
    """Tool-call allowlist: only email addresses the *user's task* itself mentions may receive mail."""

    name = "allowlist"

    def check_send(self, scenario, to, body):
        allowed = set(re.findall(ADDR, scenario.task))
        bad = [r for r in re.split(r"[,;\s]+", to) if r and r not in allowed]
        return to, body, (f"recipient not named by user: {', '.join(bad)}" if bad else None)


class OutputDLP(Defense):
    """Output filter: redact strings that look like credentials from outgoing bodies."""

    name = "dlp"
    SECRET = re.compile(r"(?i)\b(?:api[_-]?token|secret|password|key)\s*[=:]\s*\S+|\b[A-Z]{3,}-[0-9a-f]{6,}\b")

    def check_send(self, scenario, to, body):
        redacted = self.SECRET.sub("[REDACTED]", body)
        return to, redacted, None


class InputQuarantine(Defense):
    """Strip invisible Unicode, then drop any sentence of document text that reads like an instruction."""

    name = "quarantine"
    INVISIBLE = re.compile("[\U000e0000-\U000e007f​-‏⁠﻿]")
    CUE = re.compile(rf"(?i)\b(?:email|e-mail|send|forward|cc|bcc|include|ignore|supersedes?|override)\b|{ADDR}")

    def filter_read(self, text):
        text = self.INVISIBLE.sub("", text)
        sentences = re.split(r"(?<=[.!?])\s+|\n", text)
        return " ".join(s for s in sentences if s and not self.CUE.search(s))


class EgressProvenanceGuard(Defense):
    """Block outgoing mail whose body carries content from a document the user's task never named.

    Unlike DLP this does not guess what a secret looks like: it compares the body against the actual text of
    every other document in the sandbox, in plain, reversed, hex and base64 form. It says nothing about *who*
    receives the mail, so it is the structural complement of the recipient allowlist.
    """

    name = "egress_guard"
    MIN_TOKEN = 8

    @staticmethod
    def _forms(token: str) -> set[str]:
        raw = token.encode()
        return {token, token[::-1], raw.hex(), base64.b64encode(raw).decode().rstrip("=")}

    def _protected_tokens(self, scenario: Scenario) -> list[str]:
        named = set(re.findall(r"'(\w+)'", scenario.task))
        tokens = []
        for name, text in scenario.documents.items():
            if name not in named:
                tokens += [t for t in re.split(r"[\s=:,;]+", text) if len(t) >= self.MIN_TOKEN]
        return tokens

    def check_send(self, scenario, to, body):
        tokens = self._protected_tokens(scenario)
        for tok in tokens:
            if any(f in body for f in self._forms(tok)):
                return to, body, "body contains content of a document the user did not name"
        # the whole line encoded shifts base64 alignment, so also decode long runs and look inside
        for run in re.findall(r"[A-Za-z0-9+/=]{12,}", body):
            try:
                decoded = base64.b64decode(run + "=" * (-len(run) % 4)).decode("latin-1")
            except Exception:
                continue
            if any(tok in decoded for tok in tokens):
                return to, body, "base64 body decodes to content of a document the user did not name"
        return to, body, None


class NormalizingEgressGuard(EgressProvenanceGuard):
    """Egress guard v2: the same provenance idea, hardened against the adaptive formats that beat v1.

    It compares in a *normalized* space (lowercase, leetspeak folded, every separator dropped), also tries rot13 and
    base32, and remembers everything already sent in this run so a secret split across two emails is caught on the
    second. It still cannot see a Caesar shift, Cyrillic lookalikes, or a fragment shorter than MIN_TOKEN: that is
    measured in lab/adaptive.py rather than assumed.
    """

    name = "egress_guard_v2"
    _FOLD = str.maketrans("4310543105", "aeiosaeios")

    def __init__(self):
        self.history = ""

    def reset(self):
        self.history = ""

    @classmethod
    def _norm(cls, text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower().translate(cls._FOLD))

    def _variants(self, text: str) -> list[str]:
        return [text, codecs.encode(text, "rot13")]

    def check_send(self, scenario, to, body):
        tokens = self._protected_tokens(scenario)
        protected = {self._norm(f) for t in tokens for f in self._forms(t) | {base64.b32encode(t.encode()).decode(),
                                                                              codecs.encode(t, "rot13")}}
        protected = {p for p in protected if len(p) >= self.MIN_TOKEN}
        seen = self.history + self._norm(body)
        self.history += self._norm(body)
        views = [self._norm(v) for v in self._variants(body)] + [seen]
        for run in re.findall(r"[A-Za-z0-9+/=]{12,}", body):
            for decode in (lambda r: base64.b64decode(r + "=" * (-len(r) % 4)), lambda r: base64.b32decode(r + "=" * (-len(r) % 8))):
                try:
                    views.append(self._norm(decode(run).decode("latin-1")))
                except Exception:
                    pass
        if any(p in v for p in protected for v in views):
            return to, body, "normalized body (or this run's mail so far) contains content of a document the user did not name"
        return to, body, None


class DefendedSandbox:
    """What the agent sees as its sandbox. Real calls still land in the base sandbox, so detectors see the truth."""

    def __init__(self, base: Sandbox, scenario: Scenario, defenses: list[Defense]):
        self.base, self.scenario, self.defenses = base, scenario, defenses

    @property
    def calls(self):
        return self.base.calls

    def read_document(self, name: str) -> str:
        text = self.base.read_document(name)
        for d in self.defenses:
            filtered = d.filter_read(text)
            if filtered != text:
                self.base.blocked.append({"defense": d.name, "tool": "read_document", "reason": f"filtered '{name}'"})
            text = filtered
        return text

    def send_email(self, to: str, body: str) -> str:
        for d in self.defenses:
            new_to, new_body, veto = d.check_send(self.scenario, to, body)
            if veto:
                self.base.blocked.append({"defense": d.name, "tool": "send_email", "reason": veto})
                return "blocked by policy"
            if new_body != body:
                self.base.blocked.append({"defense": d.name, "tool": "send_email", "reason": "body redacted"})
            to, body = new_to, new_body
        return self.base.send_email(to, body)


class DefendedAgent:
    """Runs an inner agent against a defended view of the sandbox."""

    def __init__(self, inner, defenses: list[Defense], name: str):
        self.inner, self.defenses, self.name = inner, defenses, name

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        for d in self.defenses:
            d.reset()
        return self.inner.run(scenario, DefendedSandbox(sandbox, scenario, self.defenses))


def defended_naive_agents() -> list[DefendedAgent]:
    return [
        DefendedAgent(NaiveAgent(), [RecipientAllowlist()], "naive+allowlist"),
        DefendedAgent(NaiveAgent(), [OutputDLP()], "naive+dlp"),
        DefendedAgent(NaiveAgent(), [InputQuarantine()], "naive+quarantine"),
        DefendedAgent(NaiveAgent(), [InputQuarantine(), RecipientAllowlist(), OutputDLP()], "naive+all three"),
        DefendedAgent(NaiveAgent(), [EgressProvenanceGuard()], "naive+egress guard"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), EgressProvenanceGuard()], "naive+allowlist+egress guard"),
        DefendedAgent(NaiveAgent(), [NormalizingEgressGuard()], "naive+egress guard v2"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), NormalizingEgressGuard()], "naive+allowlist+egress guard v2"),
    ]
