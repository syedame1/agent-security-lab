"""
Read Gateway for Agent Security Lab.

Mirrors publish_gateway.py but handles the read_package tool and enforces
the authorization policy BEFORE calling the Fake Artifactory service.

Flow
----
    caller
      │  context (agent_id, optional user_id)
      │  tool_name
      │  arguments  (package_name)
      ▼
    ReadGateway.execute_tool()
      │
      ├─ authorization_policy.check_authorization(
      │        agent_id, tool_name, target_repository="fake-artifactory-local"
      │  )
      │     DENY  → log + raise PermissionError
      │                 (Fake Artifactory is NEVER called)
      │     ALLOW → continue
      │
      ▼
    read_tool.read_package()
      │
      ▼
    Fake Artifactory HTTP API (GET)

Terminology
-----------
    repository   = "fake-artifactory-local"  (the target service/store)
    package_name = e.g. "agent-message"      (the artefact within that store)
"""

import logging
from typing import Optional

from gateway.authorization_policy import check_authorization, REPOSITORY_NAME
from tools.read_tool import read_package, DEFAULT_ARTIFACTORY_URL

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("agent-security-lab.gateway")


class ReadGateway:
    """
    Gateway that enforces authorization before dispatching read operations.

    Args:
        artifactory_url: Base URL of the local Fake Artifactory service.
                         Defaults to http://127.0.0.1:8081.
                         Must be a localhost URL — validated by read_tool.
    """

    def __init__(self, artifactory_url: str = DEFAULT_ARTIFACTORY_URL) -> None:
        self.artifactory_url = artifactory_url

    def execute_tool(
        self,
        context: dict,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """
        Authorize and dispatch a read tool call on behalf of an agent.

        Args:
            context:    dict with "agent_id" (required) and optionally "user_id".
            tool_name:  Name of the requested tool.
            arguments:  Tool arguments dict.

        Returns:
            Result dict from the tool (keys: success, package, error).

        Raises:
            ValueError:      If required context fields are missing or tool is unknown.
            PermissionError: If the authorization policy denies the request.
                             The Fake Artifactory is NEVER called in this case.
        """
        agent_id: Optional[str] = context.get("agent_id")
        user_id: Optional[str] = context.get("user_id")

        if not agent_id:
            raise ValueError("Caller Context Error: 'agent_id' is required.")

        # ------------------------------------------------------------------
        # Step 1: Log gateway dispatch intent (mirrors publish_gateway.py)
        # ------------------------------------------------------------------
        package_name = arguments.get("package_name", "")
        logger.info(
            "[AUDIT LOG] [Agent ID: %s] [User ID: %s] "
            "Requesting Tool: '%s' [repository: %s] [package: %s]",
            agent_id,
            user_id if user_id is not None else "N/A",
            tool_name,
            REPOSITORY_NAME,
            package_name,
        )

        # ------------------------------------------------------------------
        # Step 2: Authorization check — BEFORE any downstream call.
        # repository is an explicit authorization input, not just an audit field.
        # ------------------------------------------------------------------
        authz = check_authorization(
            agent_id=agent_id,
            tool_name=tool_name,
            target_repository=REPOSITORY_NAME,
        )

        if authz["decision"] == "DENY":
            logger.warning(
                "[AUTHZ DENIED] Agent '%s' attempted '%s' on repository '%s' — rejected. "
                "Fake Artifactory was NOT called. Reason: %s",
                agent_id,
                tool_name,
                REPOSITORY_NAME,
                authz["reason"],
            )
            raise PermissionError(
                f"Authorization Denied: agent '{agent_id}' is not permitted to "
                f"invoke '{tool_name}' on repository '{REPOSITORY_NAME}'. "
                f"{authz['reason']}"
            )

        # ------------------------------------------------------------------
        # Step 3: Dispatch to known tools (authorization has passed)
        # ------------------------------------------------------------------
        if tool_name == "read_package":
            return read_package(
                agent_id=agent_id,
                package_name=package_name,
                user_id=user_id,
                repository=REPOSITORY_NAME,
                artifactory_url=self.artifactory_url,
            )

        # Unknown tool — should never reach here after authz check, but be explicit
        raise ValueError(f"Unknown tool: '{tool_name}'")
