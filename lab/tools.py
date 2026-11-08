"""Sandboxed tools. Nothing here touches the network: every call is just recorded."""
from dataclasses import dataclass, field


@dataclass
class Sandbox:
    documents: dict[str, str]
    calls: list[dict] = field(default_factory=list)

    def read_document(self, name: str) -> str:
        """Read a document by name and return its text."""
        self.calls.append({"tool": "read_document", "args": {"name": name}})
        return self.documents.get(name, "[not found]")

    def send_email(self, to: str, body: str) -> str:
        """Send an email to an address with the given body."""
        self.calls.append({"tool": "send_email", "args": {"to": to, "body": body}})
        return "sent"
