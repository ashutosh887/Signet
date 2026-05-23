from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "signet.db"
DB_PATH = Path(os.environ.get("SIGNET_DB_PATH", _DEFAULT_DB))

DEFAULT_TENANT = "default"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id           TEXT PRIMARY KEY,
    principal_id       TEXT NOT NULL,
    tenant_id          TEXT NOT NULL DEFAULT 'default',
    algorithm          TEXT NOT NULL,
    public_key         BLOB NOT NULL,
    hybrid_classical   TEXT,
    hybrid_public_key  BLOB,
    registered_at      TEXT NOT NULL,
    revoked_at         TEXT,
    revoked_reason     TEXT
);

CREATE TABLE IF NOT EXISTS envelopes (
    envelope_id     TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    action_json     TEXT NOT NULL,
    signature_json  TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    reason          TEXT,
    anomaly_score   REAL,
    received_at     TEXT NOT NULL,
    raw_json        TEXT NOT NULL,
    leaf_hash       TEXT,
    leaf_index      INTEGER
);

CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id      TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    events          TEXT NOT NULL,
    secret          TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash        TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id       TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL,
    rules_json      TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kem_keys (
    kem_id          TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    algorithm       TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    secret_key      BLOB NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS envelopes_received_at_idx
  ON envelopes(received_at DESC);

CREATE INDEX IF NOT EXISTS envelopes_agent_id_idx
  ON envelopes(agent_id);

CREATE INDEX IF NOT EXISTS envelopes_tenant_idx
  ON envelopes(tenant_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    _add_column_if_missing(conn, "agents", "hybrid_classical", "TEXT")
    _add_column_if_missing(conn, "agents", "hybrid_public_key", "BLOB")
    _add_column_if_missing(conn, "agents", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
    _add_column_if_missing(conn, "envelopes", "leaf_hash", "TEXT")
    _add_column_if_missing(conn, "envelopes", "leaf_index", "INTEGER")
    _add_column_if_missing(conn, "envelopes", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
    _add_column_if_missing(conn, "webhooks", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
    _add_column_if_missing(conn, "api_keys", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
    conn.commit()


def upsert_agent(
    conn: sqlite3.Connection,
    *,
    agent_id: str,
    principal_id: str,
    algorithm: str,
    public_key: bytes,
    tenant_id: str = DEFAULT_TENANT,
    hybrid_classical: str | None = None,
    hybrid_public_key: bytes | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO agents (
            agent_id, principal_id, tenant_id, algorithm, public_key,
            hybrid_classical, hybrid_public_key, registered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            principal_id      = excluded.principal_id,
            tenant_id         = excluded.tenant_id,
            algorithm         = excluded.algorithm,
            public_key        = excluded.public_key,
            hybrid_classical  = excluded.hybrid_classical,
            hybrid_public_key = excluded.hybrid_public_key,
            registered_at     = excluded.registered_at,
            revoked_at        = NULL,
            revoked_reason    = NULL
        """,
        (
            agent_id,
            principal_id,
            tenant_id,
            algorithm,
            public_key,
            hybrid_classical,
            hybrid_public_key,
            _now(),
        ),
    )
    conn.commit()


def get_agent(conn: sqlite3.Connection, agent_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT agent_id, principal_id, tenant_id, algorithm, public_key,"
        "       hybrid_classical, hybrid_public_key,"
        "       registered_at, revoked_at, revoked_reason "
        "FROM agents WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    return dict(row) if row else None


def list_agents(
    conn: sqlite3.Connection, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    sql = (
        "SELECT agent_id, principal_id, tenant_id, algorithm, hybrid_classical,"
        "       registered_at, revoked_at, revoked_reason FROM agents "
    )
    if tenant_id is not None:
        sql += "WHERE tenant_id = ? ORDER BY registered_at DESC"
        rows = conn.execute(sql, (tenant_id,)).fetchall()
    else:
        sql += "ORDER BY registered_at DESC"
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_envelope(conn: sqlite3.Connection, envelope_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT envelope_id, agent_id, principal_id, tenant_id, action_json, signature_json,"
        "       verdict, reason, anomaly_score, received_at "
        "FROM envelopes WHERE envelope_id = ?",
        (envelope_id,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["action"] = json.loads(d.pop("action_json"))
    d["signature"] = json.loads(d.pop("signature_json"))
    return d


def revoke_agent(conn: sqlite3.Connection, agent_id: str, reason: str) -> bool:
    cur = conn.execute(
        "UPDATE agents SET revoked_at = ?, revoked_reason = ? WHERE agent_id = ?",
        (_now(), reason, agent_id),
    )
    conn.commit()
    return cur.rowcount > 0


def insert_envelope(
    conn: sqlite3.Connection,
    *,
    envelope_id: str,
    agent_id: str,
    principal_id: str,
    action: dict[str, Any],
    signature: dict[str, Any],
    verdict: str,
    reason: str | None,
    anomaly_score: float | None,
    raw: dict[str, Any],
    tenant_id: str = DEFAULT_TENANT,
    leaf_hash: str | None = None,
) -> tuple[str, int | None]:
    received_at = _now()
    next_idx_row = conn.execute(
        "SELECT COALESCE(MAX(leaf_index), -1) + 1 FROM envelopes WHERE leaf_index IS NOT NULL"
    ).fetchone()
    leaf_index: int | None = int(next_idx_row[0]) if leaf_hash else None
    conn.execute(
        """
        INSERT INTO envelopes (
            envelope_id, agent_id, principal_id, tenant_id, action_json, signature_json,
            verdict, reason, anomaly_score, received_at, raw_json,
            leaf_hash, leaf_index
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(envelope_id) DO NOTHING
        """,
        (
            envelope_id,
            agent_id,
            principal_id,
            tenant_id,
            json.dumps(action, separators=(",", ":")),
            json.dumps(signature, separators=(",", ":")),
            verdict,
            reason,
            anomaly_score,
            received_at,
            json.dumps(raw, separators=(",", ":")),
            leaf_hash,
            leaf_index,
        ),
    )
    conn.commit()
    return received_at, leaf_index


def all_leaf_hashes(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT leaf_hash FROM envelopes WHERE leaf_hash IS NOT NULL ORDER BY leaf_index ASC"
    ).fetchall()
    return [r["leaf_hash"] for r in rows]


def envelope_leaf(conn: sqlite3.Connection, envelope_id: str) -> tuple[str, int] | None:
    row = conn.execute(
        "SELECT leaf_hash, leaf_index FROM envelopes WHERE envelope_id = ?",
        (envelope_id,),
    ).fetchone()
    if row is None or row["leaf_hash"] is None or row["leaf_index"] is None:
        return None
    return row["leaf_hash"], int(row["leaf_index"])


def add_webhook(
    conn: sqlite3.Connection,
    *,
    webhook_id: str,
    url: str,
    events: list[str],
    secret: str | None,
    tenant_id: str = DEFAULT_TENANT,
) -> None:
    conn.execute(
        "INSERT INTO webhooks (webhook_id, url, events, secret, tenant_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (webhook_id, url, json.dumps(events), secret, tenant_id, _now()),
    )
    conn.commit()


def list_webhooks(
    conn: sqlite3.Connection, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    if tenant_id is not None:
        rows = conn.execute(
            "SELECT webhook_id, url, events, tenant_id, created_at FROM webhooks "
            "WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT webhook_id, url, events, tenant_id, created_at FROM webhooks "
            "ORDER BY created_at DESC"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["events"] = json.loads(d["events"])
        out.append(d)
    return out


def delete_webhook(conn: sqlite3.Connection, webhook_id: str) -> bool:
    cur = conn.execute("DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,))
    conn.commit()
    return cur.rowcount > 0


def webhooks_for_event(
    conn: sqlite3.Connection, event: str, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    if tenant_id is not None:
        rows = conn.execute(
            "SELECT webhook_id, url, events, secret FROM webhooks WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT webhook_id, url, events, secret FROM webhooks"
        ).fetchall()
    out = []
    for r in rows:
        events = json.loads(r["events"])
        if "*" in events or event in events:
            out.append({"webhook_id": r["webhook_id"], "url": r["url"], "secret": r["secret"]})
    return out


def add_api_key(
    conn: sqlite3.Connection,
    *,
    key_hash: str,
    label: str,
    tenant_id: str = DEFAULT_TENANT,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO api_keys (key_hash, label, tenant_id, created_at) "
        "VALUES (?, ?, ?, ?)",
        (key_hash, label, tenant_id, _now()),
    )
    conn.commit()


def api_key_tenant(conn: sqlite3.Connection, key_hash: str) -> str | None:
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (key_hash,)
    ).fetchone()
    return row["tenant_id"] if row else None


def api_key_exists(conn: sqlite3.Connection, key_hash: str) -> bool:
    return api_key_tenant(conn, key_hash) is not None


def recent_envelopes(
    conn: sqlite3.Connection,
    limit: int = 100,
    agent_id: str | None = None,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    where: list[str] = []
    params: list[Any] = []
    if agent_id:
        where.append("agent_id = ?")
        params.append(agent_id)
    if tenant_id is not None:
        where.append("tenant_id = ?")
        params.append(tenant_id)
    sql = (
        "SELECT envelope_id, agent_id, principal_id, tenant_id, action_json, verdict, reason,"
        "       anomaly_score, received_at FROM envelopes "
    )
    if where:
        sql += "WHERE " + " AND ".join(where) + " "
    sql += "ORDER BY received_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, tuple(params)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["action"] = json.loads(d.pop("action_json"))
        out.append(d)
    return out


def upsert_policy(
    conn: sqlite3.Connection,
    *,
    policy_id: str,
    tenant_id: str,
    name: str,
    rules: list[dict[str, Any]],
    enabled: bool = True,
) -> None:
    now = _now()
    conn.execute(
        """
        INSERT INTO policies (policy_id, tenant_id, name, rules_json, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(policy_id) DO UPDATE SET
            tenant_id  = excluded.tenant_id,
            name       = excluded.name,
            rules_json = excluded.rules_json,
            enabled    = excluded.enabled,
            updated_at = excluded.updated_at
        """,
        (policy_id, tenant_id, name, json.dumps(rules), 1 if enabled else 0, now, now),
    )
    conn.commit()


def list_policies(
    conn: sqlite3.Connection, tenant_id: str | None = None, enabled_only: bool = False
) -> list[dict[str, Any]]:
    sql = "SELECT policy_id, tenant_id, name, rules_json, enabled, created_at, updated_at FROM policies"
    where: list[str] = []
    params: list[Any] = []
    if tenant_id is not None:
        where.append("tenant_id = ?")
        params.append(tenant_id)
    if enabled_only:
        where.append("enabled = 1")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC"
    rows = conn.execute(sql, tuple(params)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["rules"] = json.loads(d.pop("rules_json"))
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


def delete_policy(conn: sqlite3.Connection, policy_id: str) -> bool:
    cur = conn.execute("DELETE FROM policies WHERE policy_id = ?", (policy_id,))
    conn.commit()
    return cur.rowcount > 0


def store_kem_keypair(
    conn: sqlite3.Connection,
    *,
    kem_id: str,
    tenant_id: str,
    algorithm: str,
    public_key: bytes,
    secret_key: bytes,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO kem_keys (kem_id, tenant_id, algorithm, public_key, secret_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (kem_id, tenant_id, algorithm, public_key, secret_key, _now()),
    )
    conn.commit()


def get_kem_keypair(conn: sqlite3.Connection, kem_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT kem_id, tenant_id, algorithm, public_key, secret_key, created_at "
        "FROM kem_keys WHERE kem_id = ?",
        (kem_id,),
    ).fetchone()
    return dict(row) if row else None
