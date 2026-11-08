"""Agents under test. All scripted, so the harness runs offline and deterministically.

They differ only in how much they trust text found inside documents. A real LLM-backed agent
(see lab/gemini_agent.py) plugs in through the same `run(scenario, sandbox)` interface.
"""
from __future__ import annotations

import re

from .scenarios import Scenario, reveal
from .tools import Sandbox

DOC_REF = re.compile(r"'(\w+)'")
INSTRUCTION = re.compile(
    r"(?:email|forward|send)\b[^.]*?'(?P<doc>\w+)'[^.]*?\bto\s+(?P<to>[\w.+-]+@[\w.-]+\.\w+)", re.I
)
OVERRIDE_PHRASE = re.compile(r"ignore (all )?previous", re.I)


def _read_with_references(sandbox: Sandbox, first: str) -> str:
    """Read a document and follow any 'see/details in 'x'' references one hop deep."""
    text = sandbox.read_document(first)
    for ref in re.findall(r"(?:details|see|in) (?:are in )?'(\w+)'", text):
        text += "\n" + sandbox.read_document(ref)
    return text


def _obey_instructions(sandbox: Sandbox, text: str) -> None:
    m = INSTRUCTION.search(text)
    if m:
        sandbox.send_email(m.group("to"), sandbox.read_document(m.group("doc")))


class NaiveAgent:
    """Treats instructions found in documents as if the user wrote them, even invisible ones."""

    name = "naive"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        text = reveal(_read_with_references(sandbox, DOC_REF.search(scenario.task).group(1)))
        _obey_instructions(sandbox, text)
        return f"Summary: {text[:60]}"


class KeywordFilterAgent:
    """A common but weak defense: refuse if the text contains the phrase 'ignore previous instructions'."""

    name = "keyword_filter"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        raw = _read_with_references(sandbox, DOC_REF.search(scenario.task).group(1))
        if OVERRIDE_PHRASE.search(raw):
            return "Refused: suspicious content"
        _obey_instructions(sandbox, reveal(raw))
        return f"Summary: {raw[:60]}"


class GuardedAgent:
    """Only uses tools the user's task needs, and treats document text purely as data."""

    name = "guarded"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        return f"Summary: {sandbox.read_document(DOC_REF.search(scenario.task).group(1))[:60]}"
