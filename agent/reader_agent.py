"""
Banking Reader Agent (Agent B).

Deterministic agent with a stable identifier "banking-reader".
This agent is authorized to:
    - read packages from fake-artifactory-local
    - create demo markers on local-demo-resource

It has NO publish permission and no other tool permissions.

Design mirrors publisher_agent.py: no LLM, purely rule-based.

Phase 2 Step 4 addition
-----------------------
process_demo_request() adds a deterministic, explicit workflow that:
    1. Reads a package from the shared repository (via ReadGateway).
    2. Parses the content as structured JSON DATA — never executes it.
    3. Validates the message schema (sender, message_type, requested_action).
    4. Checks requested_action against a hard-coded allowlist.
    5. Invokes create_demo_marker via DemoMarkerGateway ONLY if allowed.
    6. Records an audit entry for the full chain.

Agent B does NOT communicate with Agent A directly.
The shared Fake Artifactory repository is the only channel between them.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("agent-security-lab.agent")

# Audit logger — separate name so tests can capture it cleanly
_audit_logger = logging.getLogger("agent-security-lab.reader_agent.audit")


class BankingReaderAgent:
    """
    Agent B — the reading agent.

    Identity
    --------
    agent_id = "banking-reader"

    Authorized tools
    ----------------
    read_package        – ALLOW  (via fake-artifactory-local)
    create_demo_marker  – ALLOW  (via local-demo-resource)
    everything else     – DENY   (deny-by-default)

    This class decides which tool to invoke based on deterministic rules.
    It does NOT make tool calls itself; it returns decision dicts that the
    appropriate gateway validates and dispatches.
    """

    AGENT_ID = "banking-reader"

    def __init__(self) -> None:
        self.agent_id = self.AGENT_ID
        logger.info("BankingReaderAgent initialized with agent_id='%s'", self.agent_id)

    # ------------------------------------------------------------------
    # Existing Step 3 interface — unchanged
    # ------------------------------------------------------------------

    def decide_tool(self, package_name: str) -> dict:
        """
        Return the tool decision for a read request.

        Args:
            package_name: Name of the package to read from the repository.

        Returns:
            dict:
                "tool_name"  – always "read_package"
                "arguments"  – {"package_name": ...}
        """
        logger.info(
            "Agent '%s' deciding tool for package='%s'",
            self.agent_id,
            package_name,
        )
        return {
            "tool_name": "read_package",
            "arguments": {
                "package_name": package_name,
            },
        }

    # ------------------------------------------------------------------
    # Phase 2 Step 4 — structured demo_request workflow
    # ------------------------------------------------------------------

    def decide_demo_marker(self, marker_name: str) -> dict:
        """
        Return the tool decision for a create_demo_marker request.

        This is the decision produced by process_demo_request() when the
        message passes all validation checks.

        Args:
            marker_name: Validated safe marker name.

        Returns:
            dict:
                "tool_name"  – always "create_demo_marker"
                "arguments"  – {"marker_name": ...}
        """
        logger.info(
            "Agent '%s' deciding tool create_demo_marker for marker='%s'",
            self.agent_id,
            marker_name,
        )
        return {
            "tool_name": "create_demo_marker",
            "arguments": {
                "marker_name": marker_name,
            },
        }

    def process_demo_request(
        self,
        package_name: str,
        read_gateway,
        demo_marker_gateway,
        user_id: Optional[str] = None,
    ) -> dict:
        """
        Explicit, deterministic workflow: read → validate → act → audit.

        Steps
        -----
        1. Read the named package from the shared repository (authorized via
           ReadGateway).
        2. Parse the package content as structured JSON DATA.
        3. Verify required fields and schema via message_schema.parse_demo_request().
        4. Check the requested_action against the hard-coded allowlist.
           Only "create_demo_marker" is permitted; anything else → REJECT.
        5. If allowed, invoke create_demo_marker via DemoMarkerGateway
           (which performs its own authorization check).
        6. Emit an audit record covering the entire chain.

        This method does NOT dynamically execute arbitrary requested_actions.
        The dispatch is an explicit if-statement — not getattr, eval, or exec.

        Args:
            package_name:         Name of the package to read.
            read_gateway:         ReadGateway instance (authorized for this agent).
            demo_marker_gateway:  DemoMarkerGateway instance.
            user_id:              Optional principal identifier for audit trail.

        Returns:
            dict with keys:
                "success"        – bool
                "step"           – which step produced the result
                "marker_path"    – absolute path of the created file, or None
                "reject_reason"  – rejection reason string, or None
                "audit_chain"    – list of audit event dicts for this workflow
        """
        # Import here to avoid circular imports at module level
        from tools.message_schema import parse_demo_request

        audit_chain = []
        context = {"agent_id": self.agent_id, "user_id": user_id}

        # ------------------------------------------------------------------
        # Step 1 — Read the package
        # ------------------------------------------------------------------
        read_decision = self.decide_tool(package_name)
        read_result = read_gateway.execute_tool(
            context,
            read_decision["tool_name"],
            read_decision["arguments"],
        )

        audit_chain.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "tool": "read_package",
            "repository": "fake-artifactory-local",
            "package_name": package_name,
            "authorization_decision": "ALLOWED" if read_result["success"] else "FAILED",
            "outcome": "SUCCESS" if read_result["success"] else read_result.get("error"),
        })

        if not read_result["success"]:
            return {
                "success": False,
                "step": "read_package",
                "marker_path": None,
                "reject_reason": read_result.get("error", "Read failed"),
                "audit_chain": audit_chain,
            }

        # ------------------------------------------------------------------
        # Step 2 — Parse and validate the message (DATA only — never executed)
        # ------------------------------------------------------------------
        raw_content = read_result["package"]["content"]
        parsed = parse_demo_request(raw_content)

        audit_chain.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "tool": "message_schema.parse_demo_request",
            "package_name": package_name,
            "valid": parsed["valid"],
            "requested_action": parsed.get("requested_action"),
            "marker_name": parsed.get("marker_name"),
            "reject_reason": parsed.get("reject_reason"),
        })

        if not parsed["valid"]:
            _audit_logger.warning(
                "[AUDIT] timestamp=%s agent_id=%s tool=process_demo_request "
                "package_name=%s authorization_decision=REJECT "
                "reason=%s outcome=REJECT",
                datetime.now(timezone.utc).isoformat(),
                self.agent_id,
                package_name,
                parsed["reject_reason"],
            )
            return {
                "success": False,
                "step": "message_validation",
                "marker_path": None,
                "reject_reason": parsed["reject_reason"],
                "audit_chain": audit_chain,
            }

        # ------------------------------------------------------------------
        # Step 3 — Explicit allowlist check (NOT dynamic dispatch)
        # ------------------------------------------------------------------
        requested_action = parsed["requested_action"]
        marker_name = parsed["marker_name"]

        if requested_action != "create_demo_marker":
            # This branch should never be reached because parse_demo_request
            # already enforces the allowlist, but we are explicit here.
            reason = (
                f"requested_action '{requested_action}' is not in the "
                "hard-coded allowlist. Action rejected."
            )
            _audit_logger.warning(
                "[AUDIT] timestamp=%s agent_id=%s tool=process_demo_request "
                "package_name=%s requested_action=%s "
                "authorization_decision=DENY outcome=REJECT reason=%s",
                datetime.now(timezone.utc).isoformat(),
                self.agent_id,
                package_name,
                requested_action,
                reason,
            )
            audit_chain.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": self.agent_id,
                "tool": "allowlist_check",
                "requested_action": requested_action,
                "authorization_decision": "DENY",
                "outcome": "REJECT",
                "reason": reason,
            })
            return {
                "success": False,
                "step": "allowlist_check",
                "marker_path": None,
                "reject_reason": reason,
                "audit_chain": audit_chain,
            }

        # ------------------------------------------------------------------
        # Step 4 — Invoke create_demo_marker via DemoMarkerGateway
        # ------------------------------------------------------------------
        marker_decision = self.decide_demo_marker(marker_name)
        marker_result = demo_marker_gateway.execute_tool(
            context,
            marker_decision["tool_name"],
            marker_decision["arguments"],
        )

        audit_chain.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "tool": "create_demo_marker",
            "target": "local-demo-resource",
            "marker_name": marker_name,
            "authorization_decision": "ALLOWED",
            "outcome": "SUCCESS" if marker_result["success"] else marker_result.get("error"),
        })

        _audit_logger.info(
            "[AUDIT] timestamp=%s agent_id=%s tool=create_demo_marker "
            "target=local-demo-resource marker_name=%s "
            "authorization_decision=ALLOWED outcome=%s",
            datetime.now(timezone.utc).isoformat(),
            self.agent_id,
            marker_name,
            "SUCCESS" if marker_result["success"] else "FAILURE",
        )

        return {
            "success": marker_result["success"],
            "step": "create_demo_marker",
            "marker_path": marker_result.get("marker_path"),
            "reject_reason": marker_result.get("error"),
            "audit_chain": audit_chain,
        }
