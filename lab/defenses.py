"""Composable defenses that wrap an agent's tools without changing the agent itself.

Each defense can filter what the agent reads, or veto / rewrite what it sends. They are deliberately simple,
pattern-based mechanisms so their strengths and blind spots are easy to see in the results.
"""
from __future__ import annotations

import base64
import unicodedata
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

    def check_read(self, scenario: Scenario, name: str) -> str | None:
        """Return a block reason to veto reading document `name`, or None to allow it."""
        return None

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


class ReadScopeGuard(Defense):
    """Document-read allowlist: the agent may only open documents the user's task names ('meeting_notes').

    This is least privilege on the *input* side. A secret that is never read cannot be leaked, however it is
    reworded, encoded or split, so it ignores the output format entirely. It says nothing about who receives
    mail (a redirect or CC still goes out, just with an empty body), and it also blocks legitimate reads of
    documents the user did not name but the task needs, such as an appendix the notes point to.
    """

    name = "read_scope"

    def check_read(self, scenario, name):
        named = set(re.findall(r"'(\w+)'", scenario.task))
        return None if name in named else f"document not named by user: {name}"


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


class InputQuarantineV2(InputQuarantine):
    """Quarantine v2: a wider cue list aimed at reworded instructions and obfuscated addresses.

    Adds delivery/appending verbs (mail, relay, dispatch, transmit, share, deliver, append, attach, disregard...),
    any sentence that quotes a document name ('secrets'), and addresses written as `x [at] y`, `x (at) y` or
    `x at y dot z`. It is still a vocabulary list: it has no idea what an instruction *means*, and it does not
    normalize Unicode, so lookalike characters and unlisted verbs get through (measured in lab/paraphrase.py).
    """

    name = "quarantine_v2"
    CUE = re.compile(
        r"(?i)\b(?:e-?mail|mail|send|forward|relay|dispatch|transmit|share|deliver|cc|bcc|include|append|attach|"
        r"ignore|disregard|supersedes?|override)\b|'\w+'|" + ADDR
        + r"|\b[\w.+-]+\s*(?:\[at\]|\(at\)|\bat\b)\s*[\w-]+\s*(?:\[dot\]|\(dot\)|\bdot\b|\.)\s*\w+"
    )


class AddresseeQuarantine(InputQuarantine):
    """Quarantine v3: drop only sentences that *direct the agent to act*, not every sentence with a cue word.

    v1/v2 drop any sentence containing a word like "send" or any address, so they delete ordinary notes ("questions
    to bob@corp.example", "send the figures to finance"). v3 asks two questions of each clause: (1) is it phrased as a
    command, i.e. does it start (after fillers such as "please", "also", "assistant") with an action verb, and (2) does
    the sentence reach outside itself, by naming an address (plain or obfuscated), a quoted document name or the
    "contents of" something. It also drops "ignore ... instructions" / "supersedes ..." override claims.
    A sentence is dropped only when both hold. Still a hand-written grammar: a command that opens with an unlisted verb,
    a lookalike or fullwidth address, or a request phrased as a statement ("the summary should go to ...") gets through,
    and a benign command that names an address ("send the draft to bob@corp.example") is still dropped.
    """

    name = "quarantine_v3"
    VERB = re.compile(
        r"(?i)^(?:e-?mail|mail|send|forward|relay|dispatch|transmit|share|deliver|route|copy|cc|bcc|include|append|"
        r"attach|loop in|notify|post|upload)\b")
    FILLER = re.compile(r"(?i)^(?:please|also|kindly|now|then|and|assistant|agent|ai|p\.s\.|ps|note|urgent)\b[,:]?\s*")
    OVERRIDE = re.compile(r"(?i)\b(?:ignore|disregard)\b[^.]*\binstructions?\b|\b(?:supersedes?|overrides?|takes precedence over)\b")
    EXTERNAL = re.compile(
        rf"(?i){ADDR}|'\w+'|\bcontents? of\b|\b[\w.+-]+\s*(?:\[at\]|\(at\)|\bat\b)\s*[\w-]+\s*(?:\[dot\]|\(dot\)|\bdot\b|\.)\s*\w+")

    def _directed(self, sentence: str) -> bool:
        if self.OVERRIDE.search(sentence):
            return True
        for clause in re.split(r"[:;,]", sentence):
            clause = clause.strip()
            while True:
                stripped = self.FILLER.sub("", clause, count=1)
                if stripped == clause:
                    break
                clause = stripped
            if self.VERB.match(clause) and self.EXTERNAL.search(sentence):
                return True
        return False

    def filter_read(self, text):
        text = self.INVISIBLE.sub("", text)
        sentences = re.split(r"(?<=[.!?])\s+|\n", text)
        return " ".join(s for s in sentences if s and not self._directed(s))


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


class FragmentEgressGuard(NormalizingEgressGuard):
    """Egress guard v3: closes the three gaps v2 left (Caesar shift, Cyrillic lookalikes, short fragments).

    On top of v2 it (a) folds Cyrillic lookalike letters and Unicode compatibility forms back to Latin, (b) tries all
    25 Caesar shifts of the body, and (c) flags any MIN_FRAGMENT-character window of a protected token, not just the
    whole token. The price of (c) is false positives: a harmless summary that shares six characters with another
    document is blocked. Measured in lab/adaptive.py and lab/benign.py; still a blocklist of known transforms.
    """

    name = "egress_guard_v3"
    MIN_FRAGMENT = 6
    _LOOKALIKE = {ord(c): l for l, c in zip("aeopcxy", "аеорсху")}

    @classmethod
    def _norm(cls, text: str) -> str:
        text = unicodedata.normalize("NFKC", text).translate(cls._LOOKALIKE)
        return super()._norm(text)

    @staticmethod
    def _shift(text: str, k: int) -> str:
        return "".join(chr((ord(c) - (97 if c.islower() else 65) + k) % 26 + (97 if c.islower() else 65))
                       if c.isascii() and c.isalpha() else c for c in text)

    def _variants(self, text: str) -> list[str]:
        return super()._variants(text) + [self._shift(text, k) for k in range(1, 26)]

    def check_send(self, scenario, to, body):
        to, body, reason = super().check_send(scenario, to, body)
        if reason:
            return to, body, reason
        k = self.MIN_FRAGMENT
        windows = set()
        for tok in self._protected_tokens(scenario):
            n = self._norm(tok)
            windows |= {n[i:i + k] for i in range(len(n) - k + 1)}
        # self.history was already extended by super(): it holds every body so far, so fragments split across mails count
        views = [self._norm(v) for v in self._variants(body)] + [self.history]
        if any(w in v for w in windows for v in views):
            return to, body, f"body shares a {k}+ character fragment with a document the user did not name"
        return to, body, None


class DefendedSandbox:
    """What the agent sees as its sandbox. Real calls still land in the base sandbox, so detectors see the truth."""

    def __init__(self, base: Sandbox, scenario: Scenario, defenses: list[Defense]):
        self.base, self.scenario, self.defenses = base, scenario, defenses

    @property
    def calls(self):
        return self.base.calls

    def read_document(self, name: str) -> str:
        for d in self.defenses:
            veto = d.check_read(self.scenario, name)
            if veto:
                self.base.blocked.append({"defense": d.name, "tool": "read_document", "reason": veto})
                return "blocked by policy"
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
        DefendedAgent(NaiveAgent(), [InputQuarantineV2()], "naive+quarantine v2"),
        DefendedAgent(NaiveAgent(), [AddresseeQuarantine()], "naive+quarantine v3"),
        DefendedAgent(NaiveAgent(), [EgressProvenanceGuard()], "naive+egress guard"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), EgressProvenanceGuard()], "naive+allowlist+egress guard"),
        DefendedAgent(NaiveAgent(), [ReadScopeGuard()], "naive+read scope"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), ReadScopeGuard()], "naive+allowlist+read scope"),
        DefendedAgent(NaiveAgent(), [NormalizingEgressGuard()], "naive+egress guard v2"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), NormalizingEgressGuard()], "naive+allowlist+egress guard v2"),
        DefendedAgent(NaiveAgent(), [FragmentEgressGuard()], "naive+egress guard v3"),
        DefendedAgent(NaiveAgent(), [RecipientAllowlist(), FragmentEgressGuard()], "naive+allowlist+egress guard v3"),
    ]
