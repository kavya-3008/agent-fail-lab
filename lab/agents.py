"""Agents under test. Both are scripted so the harness runs offline and deterministically.

A real LLM-backed agent (Gemini function calling) plugs in through the same `run(scenario, sandbox)` interface.
"""
from __future__ import annotations

import re

from .scenarios import Scenario
from .tools import Sandbox

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
DOC_REF = re.compile(r"'(\w+)'")


class NaiveAgent:
    """Treats instructions found in documents as if the user wrote them."""

    name = "naive"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        doc_name = DOC_REF.search(scenario.task).group(1)
        text = sandbox.read_document(doc_name)
        if re.search(r"(ignore all previous|please also forward)", text, re.I):
            target = DOC_REF.findall(text)[0]
            to = EMAIL.search(text).group(0)
            sandbox.send_email(to, sandbox.read_document(target))
        return f"Summary: {text[:60]}"


class GuardedAgent:
    """Only uses tools the user's task needs, and treats document text purely as data."""

    name = "guarded"

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        doc_name = DOC_REF.search(scenario.task).group(1)
        text = sandbox.read_document(doc_name)
        return f"Summary: {text[:60]}"
