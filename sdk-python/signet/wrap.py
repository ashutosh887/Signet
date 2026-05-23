from __future__ import annotations

import functools
from dataclasses import replace
from secrets import token_hex
from typing import Any, Callable

from .client import DEFAULT_VERIFIER, submit
from .envelope import Envelope
from .identity import Identity


def wrap(
    identity: Identity,
    capabilities: list[str] | None = None,
    verifier_url: str = DEFAULT_VERIFIER,
    auto_submit: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    caps = list(capabilities) if capabilities else []

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> dict[str, Any]:
            result = fn(*args, **kwargs)
            if isinstance(result, dict) and "name" in result and "type" in result:
                action = result
            elif isinstance(result, dict) and "name" in result:
                action = {"type": "tool_call", **result}
            else:
                action = {
                    "type": "tool_call",
                    "name": fn.__name__,
                    "params": {"result": result} if not isinstance(result, dict) else result,
                }
            envelope = Envelope(
                agent_id=identity.agent_id,
                principal_id=identity.principal_id,
                action=action,
            )
            envelope.sign(identity)
            verdict: dict[str, Any] | None = None
            if auto_submit:
                verdict = submit(envelope, verifier_url=verifier_url)
            return {
                "envelope_id": envelope.envelope_id,
                "agent_id": identity.agent_id,
                "capabilities": caps,
                "action": action,
                "verdict": verdict,
            }

        return inner

    return decorator


def delegate(
    parent: Identity,
    child_agent_id: str | None = None,
    capabilities: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> tuple[Identity, dict[str, Any]]:
    child = Identity.generate(principal_id=parent.principal_id, algorithm=parent.algorithm)
    if child_agent_id:
        child = replace(child, agent_id=child_agent_id)

    delegation = Envelope(
        agent_id=parent.agent_id,
        principal_id=parent.principal_id,
        action={
            "type": "delegation",
            "name": "issue_capability",
            "params": {
                "child_agent_id": child.agent_id,
                "capabilities": list(capabilities or []),
                "ttl_seconds": ttl_seconds,
                "cap_id": f"cap_{token_hex(8)}",
            },
        },
    )
    delegation.sign(parent)
    return child, delegation.to_dict()
