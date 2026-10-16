"""User accounts and subscription plans, stored as (:User) nodes in their own graph."""
import time
from typing import Any

from .db import ACCOUNTS_GRAPH, run


def get_account(user_id: str) -> dict[str, Any]:
    rows = run(
        "MATCH (u:User {id: $id}) RETURN u.plan, u.email, u.customer_id, u.updated_at",
        {"id": user_id},
        graph=ACCOUNTS_GRAPH,
    )
    if not rows:
        return {"user_id": user_id, "plan": "free", "email": None, "customer_id": None, "updated_at": None}
    plan, email, customer_id, updated_at = rows[0]
    return {"user_id": user_id, "plan": plan or "free", "email": email, "customer_id": customer_id, "updated_at": updated_at}


def upsert_account(user_id: str, plan: str, email: str | None, customer_id: str | None) -> dict[str, Any]:
    """Create or update a user. Omitted email / customer_id keep their previous values."""
    run(
        """MERGE (u:User {id: $id})
           SET u.plan = $plan, u.email = coalesce($email, u.email),
               u.customer_id = coalesce($cid, u.customer_id), u.updated_at = $ts""",
        {"id": user_id, "plan": plan, "email": email, "cid": customer_id, "ts": int(time.time() * 1000)},
        graph=ACCOUNTS_GRAPH,
    )
    return get_account(user_id)


def find_by_customer(customer_id: str) -> str | None:
    rows = run("MATCH (u:User {customer_id: $c}) RETURN u.id", {"c": customer_id}, graph=ACCOUNTS_GRAPH)
    return rows[0][0] if rows else None
