from __future__ import annotations

from typing import Any, Awaitable, Callable

from .client import DEFAULT_VERIFIER, submit
from .envelope import Envelope
from .identity import Identity


ToolHandler = Callable[[str, dict[str, Any]], Any] | Callable[[str, dict[str, Any]], Awaitable[Any]]


class SignetMCPMiddleware:
    """Wraps an MCP-style tool invocation in a Signet action envelope.

    Drop into any host that dispatches `(tool_name, params) -> result`:

        mcp = SignetMCPMiddleware(identity)
        result = mcp.invoke("book_meeting", {"date": "2026-05-24"}, handler=run_tool)

    A2A (agent-to-agent) callers use the same interface — the envelope
    captures `principal_id`, action name + params, and is verified before
    the host actually runs the tool. Result of the underlying call is
    returned to the caller unmodified; the verdict is attached.
    """

    def __init__(
        self,
        identity: Identity,
        *,
        verifier_url: str = DEFAULT_VERIFIER,
        protocol: str = "mcp",
    ) -> None:
        self.identity = identity
        self.verifier_url = verifier_url
        self.protocol = protocol

    def envelope_for(self, tool_name: str, params: dict[str, Any]) -> Envelope:
        env = Envelope(
            agent_id=self.identity.agent_id,
            principal_id=self.identity.principal_id,
            action={
                "type": "tool_call",
                "name": tool_name,
                "params": params,
                "protocol": self.protocol,
            },
        )
        env.sign(self.identity)
        return env

    def invoke(
        self,
        tool_name: str,
        params: dict[str, Any],
        handler: ToolHandler,
    ) -> dict[str, Any]:
        envelope = self.envelope_for(tool_name, params)
        verdict = submit(envelope, verifier_url=self.verifier_url)
        if not verdict.get("valid"):
            return {
                "envelope_id": envelope.envelope_id,
                "verdict": verdict,
                "result": None,
                "executed": False,
            }
        result = handler(tool_name, params)
        return {
            "envelope_id": envelope.envelope_id,
            "verdict": verdict,
            "result": result,
            "executed": True,
        }
