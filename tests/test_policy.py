from signet_verifier import policy


def test_default_allow_when_no_rules() -> None:
    d = policy.evaluate([], {"action_name": "x"})
    assert d.allowed is True
    assert d.rule_id is None


def test_first_match_wins_deny() -> None:
    rules = [
        {"id": "deny_rm", "effect": "deny", "match": {"action_name": "rm_rf*"},
         "reason": "destructive"},
        {"id": "allow", "effect": "allow"},
    ]
    d = policy.evaluate(rules, {"action_name": "rm_rf_root"})
    assert d.allowed is False
    assert d.rule_id == "deny_rm"
    assert d.reason == "destructive"


def test_match_on_glob_and_params() -> None:
    rules = [
        {"id": "deny_high_value",
         "effect": "deny",
         "match": {"action_name": "transfer", "params": {"amount": [10_000, 20_000]}},
         "reason": "amount_above_limit"},
        {"id": "allow", "effect": "allow"},
    ]
    d = policy.evaluate(rules, {"action_name": "transfer", "params": {"amount": 10_000}})
    assert d.allowed is False
    d2 = policy.evaluate(rules, {"action_name": "transfer", "params": {"amount": 50}})
    assert d2.allowed is True


def test_disabled_rule_skipped() -> None:
    rules = [
        {"id": "off", "effect": "deny", "enabled": False, "match": {"action_name": "x"}},
        {"id": "allow", "effect": "allow"},
    ]
    d = policy.evaluate(rules, {"action_name": "x"})
    assert d.allowed is True


def test_multiple_policies_any_deny_blocks() -> None:
    policies = [
        {"rules": [{"id": "p1_allow", "effect": "allow"}]},
        {"rules": [{"id": "p2_deny", "effect": "deny", "match": {"action_name": "x"},
                    "reason": "blocked"}]},
    ]
    d = policy.evaluate_policies(policies, {"action_name": "x"})
    assert d.allowed is False
    assert d.rule_id == "p2_deny"
