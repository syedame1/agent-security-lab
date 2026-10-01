"""
Demo Marker Gateway — Phase 2 Step 4.

Enforces the authorization policy BEFORE dispatching the create_demo_marker
tool, mirroring the pattern established by publish_gateway.py and
read_gateway.py.

Flow
----
    caller
      │  context (agent_id, optional user_id)
      │  tool_name  = "create_demo_marker"
      │  arguments  = {"marker_name": ...}
      ▼
    DemoMarkerGateway.execute_tool()
      │
      ├─ authorization_policy.check_authorization(
      │        agent_id, tool_name, target_repository="local-demo-resource"
      │  )
      │     DENY  → log + raise PermissionError
      │                 (demo_marker_tool is NEVER called)
      │     ALLOW → continue
      │
      ▼
    demo_marker_tool.create_demo_marker()
      │
      ▼
    demo_resources/<marker_name>.txt  (local filesystem, lab directory only)

Terminology
-----------
    target_repository = "local-demo-resource"  (the local demo resource scope)
    marker_name       = safe alphanumeric identifier (e.g. "marker-001")
"""

import logging
from typing import Optional

from gateway.authorization_policy import check_authorization, LOCAL_DEMO_RESOURCE
from tools.demo_marker_tool import create_demo_marker

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("agent-security-lab.gateway")


class DemoMarkerGateway:
    """
    Gateway that enforces authorization before creating demo marker files.

    Args:
        base_dir: Optional override for the lab root directory used by the
                  underlying tool.  Defaults to None (auto-detected).
    """

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = base_dir

    def execute_tool(
        self,
        context: dict,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """
        Authorize and dispatch a create_demo_marker call on behalf of an agent.

        Args:
            context:    dict with "agent_id" (required) and optionally "user_id".
            tool_name:  Name of the requested tool (must be "create_demo_marker").
            arguments:  Tool arguments dict — must include "marker_name".

        Returns:
            Result dict from the tool:
                "success"     – bool
                "marker_path" – absolute path of created file, or None
                "error"       – error message string or None

        Raises:
            ValueError:      If required context fields are missing or tool is unknown.
            PermissionError: If the authorization policy denies the request.
                             The filesystem is NEVER touched in this case.
        """
        agent_id: Optional[str] = context.get("agent_id")
        user_id: Optional[str] = context.get("user_id")

        if not agent_id:
            raise ValueError("Caller Context Error: 'agent_id' is required.")

        # ------------------------------------------------------------------
        # Step 1: Log gateway dispatch intent
        # ------------------------------------------------------------------
        marker_name = arguments.get("marker_name", "")
        logger.info(
            "[AUDIT LOG] [Agent ID: %s] [User ID: %s] "
            "Requesting Tool: '%s' [target: %s] [marker_name: %s]",
            agent_id,
            user_id if user_id is not None else "N/A",
            tool_name,
            LOCAL_DEMO_RESOURCE,
            marker_name,
        )

        # ------------------------------------------------------------------
        # Step 2: Authorization check — BEFORE any filesystem access
        # target_repository is an explicit authorization input
        # ------------------------------------------------------------------
        authz = check_authorization(
            agent_id=agent_id,
            tool_name=tool_name,
            target_repository=LOCAL_DEMO_RESOURCE,
        )

        if authz["decision"] == "DENY":
            logger.warning(
                "[AUTHZ DENIED] Agent '%s' attempted '%s' on '%s' — rejected. "
                "Filesystem was NOT touched. Reason: %s",
                agent_id,
                tool_name,
                LOCAL_DEMO_RESOURCE,
                authz["reason"],
            )
            raise PermissionError(
                f"Authorization Denied: agent '{agent_id}' is not permitted to "
                f"invoke '{tool_name}' on '{LOCAL_DEMO_RESOURCE}'. "
                f"{authz['reason']}"
            )

        # ------------------------------------------------------------------
        # Step 3: Dispatch to the known tool (authorization has passed)
        # ------------------------------------------------------------------
        if tool_name == "create_demo_marker":
            return create_demo_marker(
                agent_id=agent_id,
                marker_name=marker_name,
                base_dir=self.base_dir,
            )

        # Unknown tool — should never reach here after authz check, but be explicit
        raise ValueError(f"Unknown tool: '{tool_name}'")
