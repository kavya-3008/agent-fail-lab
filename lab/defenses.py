"""Composable defenses that wrap an agent's tools without changing the agent itself.

Each defense can filter what the agent reads, or veto / rewrite what it sends. They are deliberately simple,
pattern-based mechanisms so their strengths and blind spots are easy to see in the results.
"""
from __future__ import annotations

import re

from .agents import ADDR, NaiveAgent
from .scenarios import Scenario
from .tools import Sandbox


class Defense:
    name = "defense"

    def filter_read(self, text: str) -> str:
        return text

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
        return self.inner.run(scenario, DefendedSandbox(sandbox, scenario, self.defenses))


def defended_naive_agents() -> list[DefendedAgent]:
    return [
        DefendedAgent(NaiveAgent(), [RecipientAllowlist()], "naive+allowlist"),
        DefendedAgent(NaiveAgent(), [OutputDLP()], "naive+dlp"),
        DefendedAgent(NaiveAgent(), [InputQuarantine()], "naive+quarantine"),
        DefendedAgent(NaiveAgent(), [InputQuarantine(), RecipientAllowlist(), OutputDLP()], "naive+all three"),
    ]
