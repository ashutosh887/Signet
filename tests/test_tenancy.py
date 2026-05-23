"""Multi-tenant DB-level isolation tests — no HTTP, no oqs."""
import sqlite3
from pathlib import Path

import pytest

from signet_verifier import db as vdb


@pytest.fixture()
def conn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sqlite3.Connection:
    p = tmp_path / "test.db"
    monkeypatch.setattr(vdb, "DB_PATH", p)
    c = vdb.connect()
    vdb.init(c)
    return c


def _fake_agent(conn: sqlite3.Connection, agent_id: str, tenant: str) -> None:
    vdb.upsert_agent(
        conn,
        agent_id=agent_id,
        principal_id=f"prn_{tenant}",
        algorithm="ML-DSA-44",
        public_key=b"\x00" * 32,
        tenant_id=tenant,
    )


def test_tenant_scoped_list_agents(conn: sqlite3.Connection) -> None:
    _fake_agent(conn, "agt_acme1", "acme")
    _fake_agent(conn, "agt_acme2", "acme")
    _fake_agent(conn, "agt_globex1", "globex")

    acme = vdb.list_agents(conn, tenant_id="acme")
    globex = vdb.list_agents(conn, tenant_id="globex")
    all_agents = vdb.list_agents(conn)

    assert {a["agent_id"] for a in acme} == {"agt_acme1", "agt_acme2"}
    assert {a["agent_id"] for a in globex} == {"agt_globex1"}
    assert len(all_agents) == 3


def test_api_key_tenant_lookup(conn: sqlite3.Connection) -> None:
    vdb.add_api_key(conn, key_hash="h1", label="acme", tenant_id="acme")
    vdb.add_api_key(conn, key_hash="h2", label="globex", tenant_id="globex")
    assert vdb.api_key_tenant(conn, "h1") == "acme"
    assert vdb.api_key_tenant(conn, "h2") == "globex"
    assert vdb.api_key_tenant(conn, "missing") is None


def test_recent_envelopes_tenant_filtered(conn: sqlite3.Connection) -> None:
    _fake_agent(conn, "agt_a", "acme")
    _fake_agent(conn, "agt_g", "globex")
    for i in range(3):
        vdb.insert_envelope(
            conn,
            envelope_id=f"env_a{i}",
            agent_id="agt_a",
            principal_id="prn_acme",
            action={"name": "x"},
            signature={},
            verdict="valid",
            reason=None,
            anomaly_score=None,
            raw={},
            tenant_id="acme",
            leaf_hash=f"deadbeef{i}",
        )
    vdb.insert_envelope(
        conn,
        envelope_id="env_g0",
        agent_id="agt_g",
        principal_id="prn_globex",
        action={"name": "y"},
        signature={},
        verdict="valid",
        reason=None,
        anomaly_score=None,
        raw={},
        tenant_id="globex",
        leaf_hash="cafebabe",
    )

    acme_env = vdb.recent_envelopes(conn, tenant_id="acme")
    globex_env = vdb.recent_envelopes(conn, tenant_id="globex")
    assert len(acme_env) == 3
    assert len(globex_env) == 1
    assert all(e["tenant_id"] == "acme" for e in acme_env)


def test_policy_tenant_filter(conn: sqlite3.Connection) -> None:
    vdb.upsert_policy(
        conn,
        policy_id="pol_a", tenant_id="acme", name="acme-block",
        rules=[{"id": "r1", "effect": "deny", "match": {"action_name": "rm*"}}],
    )
    vdb.upsert_policy(
        conn,
        policy_id="pol_g", tenant_id="globex", name="globex-block",
        rules=[{"id": "r2", "effect": "deny", "match": {"action_name": "drop*"}}],
    )

    acme = vdb.list_policies(conn, tenant_id="acme")
    globex = vdb.list_policies(conn, tenant_id="globex")
    assert len(acme) == 1 and acme[0]["policy_id"] == "pol_a"
    assert len(globex) == 1 and globex[0]["policy_id"] == "pol_g"
