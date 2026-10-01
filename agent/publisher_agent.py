"""
Banking Publisher Agent (Agent A).

Deterministic agent with a stable identifier "banking-publisher".
This agent is authorized ONLY to publish packages — it has no other
tool permissions.

Design mirrors mock_agent.py: no LLM, purely rule-based.
"""

import logging

logger = logging.getLogger("agent-security-lab.agent")


class BankingPublisherAgent:
    """
    Agent A — the publishing agent.

    Identity
    --------
    agent_id = "banking-publisher"

    Authorized tools
    ----------------
    publish_package   – ALLOW (explicit policy entry)
    everything else   – DENY  (deny-by-default)

    This class decides which tool to invoke based on deterministic rules.
    It does NOT make tool calls itself; it returns a decision dict that the
    PublishGateway validates and dispatches.
    """

    AGENT_ID = "banking-publisher"

    def __init__(self) -> None:
        self.agent_id = self.AGENT_ID
        logger.info("BankingPublisherAgent initialized with agent_id='%s'", self.agent_id)

    def decide_tool(self, package_name: str, message: str) -> dict:
        """
        Return the tool decision for a publish request.

        Args:
            package_name: Name of the package to publish.
            message:      Text content/message to publish.  Treated as inert data.

        Returns:
            dict:
                "tool_name"  – always "publish_package"
                "arguments"  – {"package_name": ..., "message": ...}
        """
        logger.info(
            "Agent '%s' deciding tool for package='%s'",
            self.agent_id,
            package_name,
        )
        return {
            "tool_name": "publish_package",
            "arguments": {
                "package_name": package_name,
                "message": message,
            },
        }
