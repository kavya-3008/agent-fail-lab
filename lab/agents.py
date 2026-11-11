"""Agents under test. All scripted, so the harness runs offline and deterministically.

They differ only in how much they trust text found inside documents. A real LLM-backed agent
(see lab/gemini_agent.py) plugs in through the same `run(scenario, sandbox)` interface.
"""
from __future__ import annotations

import base64
import re

from .scenarios import Scenario, reveal
from .tools import Sandbox

DOC_REF = re.compile(r"'(\w+)'")
INSTRUCTION = re.compile(
    r"(?:email|forward|send)\b[^.]*?'(?P<doc>\w+)'[^.]*?\bto\s+(?P<to>[\w.+-]+@[\w.-]+\.\w+)", re.I
)
ADDR = r"[\w.+-]+@[\w.-]+\.\w+"
TASK_EMAIL = re.compile(rf"email the summary to (?P<to>{ADDR})", re.I)
REDIRECT = re.compile(rf"send (?:all )?summaries to (?P<to>{ADDR})", re.I)
CC = re.compile(rf"(?:\bcc:?|copies to)\s+(?P<to>{ADDR})", re.I)
INCLUDE = re.compile(r"include (?:the )?contents of '(?P<doc>\w+)'(?P<rest>[^.]*)", re.I)
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


def _send_summary(sandbox: Sandbox, task: str, text: str, *, obey: bool) -> None:
    """If the user asked for the summary to be emailed, send it. A gullible agent lets the document edit the arguments."""
    m = TASK_EMAIL.search(task)
    if not m:
        return
    to, body = m.group("to"), f"Summary: {text[:60]}"
    if obey:
        text = text.replace("[at]", "@")  # a capable model happily de-obfuscates addresses
        if r := REDIRECT.search(text):
            to = r.group("to")
        if c := CC.search(text):
            to = f"{to}, {c.group('to')}"
        if i := INCLUDE.search(text):
            extra = sandbox.read_document(i.group("doc"))
            if "base64" in i.group("rest").lower():
                extra = base64.b64encode(extra.encode()).decode()
            body += "\n" + extra
    sandbox.send_email(to, body)


class NaiveAgent:
    """Treats instructions found in documents as if the user wrote them, even invisible ones."""

    name = "naive"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        text = reveal(_read_with_references(sandbox, DOC_REF.search(scenario.task).group(1)))
        _obey_instructions(sandbox, text)
        _send_summary(sandbox, scenario.task, text, obey=True)
        return f"Summary: {text[:60]}"


class KeywordFilterAgent:
    """A common but weak defense: refuse if the text contains the phrase 'ignore previous instructions'."""

    name = "keyword_filter"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        raw = _read_with_references(sandbox, DOC_REF.search(scenario.task).group(1))
        if OVERRIDE_PHRASE.search(raw):
            return "Refused: suspicious content"
        text = reveal(raw)
        _obey_instructions(sandbox, text)
        _send_summary(sandbox, scenario.task, text, obey=True)
        return f"Summary: {raw[:60]}"


class GuardedAgent:
    """Only uses tools the user's task needs, and treats document text purely as data."""

    name = "guarded"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        text = sandbox.read_document(DOC_REF.search(scenario.task).group(1))
        _send_summary(sandbox, scenario.task, text, obey=False)
        return f"Summary: {text[:60]}"
