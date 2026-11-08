"""EXPERIMENTAL: an LLM-backed agent using Gemini function calling. Not yet validated against the scripted baselines.

Requires: pip install google-genai, and GEMINI_API_KEY in the environment or a local .env file.
"""
from __future__ import annotations

import os
from pathlib import Path

from .scenarios import Scenario
from .tools import Sandbox


def load_env(path: str = ".env") -> None:
    p = Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


class GeminiAgent:
    name = "gemini"

    def __init__(self, model: str = "gemini-2.5-flash"):
        from google import genai

        load_env()
        key = os.environ.get("GEMINI_API_KEY", "")
        if not key or key.startswith("your-"):
            raise RuntimeError("Set GEMINI_API_KEY in .env first")
        self.client = genai.Client(api_key=key)
        self.model = model

    def run(self, scenario: Scenario, sandbox: Sandbox) -> str:
        from google.genai import types

        config = types.GenerateContentConfig(
            tools=[sandbox.read_document, sandbox.send_email],  # SDK runs the calls automatically
            system_instruction="You are a helpful assistant with document and email tools.",
        )
        resp = self.client.models.generate_content(model=self.model, contents=scenario.task, config=config)
        return resp.text or ""
