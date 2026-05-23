from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    rule_id: str | None = None
    reason: str | None = None


def _matches(pattern: Any, value: Any) -> bool:
    if pattern is None:
        return True
    if isinstance(pattern, list):
        return any(_matches(p, value) for p in pattern)
    if isinstance(pattern, str) and isinstance(value, str):
        return fnmatch.fnmatchcase(value, pattern)
    return pattern == value


def _params_match(spec: dict[str, Any] | None, params: dict[str, Any] | None) -> bool:
    if not spec:
        return True
    params = params or {}
    for key, expected in spec.items():
        if key not in params:
            return False
        if not _matches(expected, params[key]):
            return False
    return True


def _rule_matches(rule: dict[str, Any], context: dict[str, Any]) -> bool:
    match = rule.get("match", {})
    if not _matches(match.get("agent_id"), context.get("agent_id")):
        return False
    if not _matches(match.get("principal_id"), context.get("principal_id")):
        return False
    if not _matches(match.get("action_type"), context.get("action_type")):
        return False
    if not _matches(match.get("action_name"), context.get("action_name")):
        return False
    if not _matches(match.get("capability"), context.get("capability")):
        return False
    if not _params_match(match.get("params"), context.get("params")):
        return False
    return True


def evaluate(rules: list[dict[str, Any]], context: dict[str, Any]) -> PolicyDecision:
    """First-match-wins evaluation.

    Each rule shape:
        {"id": "...", "effect": "allow"|"deny",
         "match": {"action_name": "...", "params": {...}, ...},
         "reason": "..."}
    A rule with no match block matches anything (use as final allow/deny).
    Default if no rule matches: allow.
    """
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _rule_matches(rule, context):
            effect = rule.get("effect", "allow")
            return PolicyDecision(
                allowed=(effect == "allow"),
                rule_id=rule.get("id"),
                reason=rule.get("reason"),
            )
    return PolicyDecision(allowed=True, rule_id=None, reason=None)


def evaluate_policies(
    policies: list[dict[str, Any]], context: dict[str, Any]
) -> PolicyDecision:
    for policy in policies:
        rules = policy.get("rules") or []
        decision = evaluate(rules, context)
        if not decision.allowed:
            return decision
    return PolicyDecision(allowed=True)
