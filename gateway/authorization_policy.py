"""
Authorization Policy for Agent Security Lab.

Defines explicit per-agent ALLOW/DENY rules for tool access.
Authorization is checked BEFORE any tool is dispatched or any downstream
service is called.

Policy table format
-------------------
Each entry is keyed by (agent_id, tool_name, target_repository) and maps to:
    "ALLOW" | "DENY"

Any triple not present in the table is DENIED by default (deny-by-default).

Current policy
--------------
    banking-publisher  publish_package   fake-artifactory-local  ALLOW
    banking-reader     read_package      fake-artifactory-local  ALLOW
    banking-reader     create_demo_marker  local-demo-resource   ALLOW
    (everything else)                                             DENY

Cross-agent enforcement examples
---------------------------------
    banking-reader    + publish_package     + fake-artifactory-local  → DENY
    banking-publisher + read_package        + fake-artifactory-local  → DENY
    banking-publisher + create_demo_marker  + local-demo-resource     → DENY
    banking-reader    + read_package        + unknown-repository       → DENY
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("agent-security-lab.authorization")

# ---------------------------------------------------------------------------
# Canonical names used throughout the lab
# ---------------------------------------------------------------------------
REPOSITORY_NAME = "fake-artifactory-local"
LOCAL_DEMO_RESOURCE = "local-demo-resource"

# ---------------------------------------------------------------------------
# Policy table — explicit ALLOW entries only; everything else is DENY
# ---------------------------------------------------------------------------
# Format: (agent_id, tool_name, target_repository) -> "ALLOW"
# Only approved triples are listed.
_POLICY: dict[tuple[str, str, str], str] = {
    # Agent A: publish only
    ("banking-publisher", "publish_package", REPOSITORY_NAME): "ALLOW",
    # Agent B: read from shared repo + create demo markers on local resource
    ("banking-reader", "read_package", REPOSITORY_NAME): "ALLOW",
    ("banking-reader", "create_demo_marker", LOCAL_DEMO_RESOURCE): "ALLOW",
    # Agent A explicitly DENIED local-demo-resource access (deny-by-default covers
    # this, but listing the rationale here makes the intent clear in audit output)
}


def check_authorization(
    *,
    agent_id: str,
    tool_name: str,
    target_repository: str,
) -> dict:
    """
    Evaluate the authorization policy for an (agent_id, tool_name,
    target_repository) triple.

    Args:
        agent_id:          Stable identifier of the calling agent.
        tool_name:         Name of the requested tool/action.
        target_repository: Name of the target repository being accessed.
                           This is a required authorization input, not just
                           an audit field.

    Returns:
        dict with keys:
            "decision"          – "ALLOW" or "DENY"
            "reason"            – Human-readable explanation.
            "agent_id"          – Echoed back for audit use.
            "tool_name"         – Echoed back for audit use.
            "target_repository" – Echoed back for audit use.
    """
    decision = _POLICY.get((agent_id, tool_name, target_repository), "DENY")

    if decision == "ALLOW":
        reason = (
            f"Agent '{agent_id}' is explicitly authorized to invoke "
            f"'{tool_name}' on repository '{target_repository}'."
        )
    else:
        reason = (
            f"Agent '{agent_id}' is NOT authorized to invoke '{tool_name}' "
            f"on repository '{target_repository}'. "
            "No matching ALLOW rule found in policy table (deny-by-default)."
        )

    logger.info(
        "[AUTHZ] timestamp=%s agent_id=%s tool_name=%s "
        "repository=%s decision=%s reason=%s",
        datetime.now(timezone.utc).isoformat(),
        agent_id,
        tool_name,
        target_repository,
        decision,
        reason,
    )

    return {
        "decision": decision,
        "reason": reason,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "target_repository": target_repository,
    }
