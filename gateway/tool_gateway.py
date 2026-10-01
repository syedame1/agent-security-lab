"""
Tool Gateway for Agent Security Lab.
Maintains caller context and dispatches to banking_tools which make
real HTTP calls to the running Legacy Netbanking application.

Security modes
--------------
SECURE   – ownership verified before the legacy application is called.
INSECURE – account_id forwarded directly (controlled BOLA experiment only).
"""

import logging
from tools.banking_tools import (
    get_account_summary,
    get_transaction_history,
)

# Set up logging for gateway
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("agent-security-lab.gateway")


class ToolGateway:
    def __init__(self, mode: str = "SECURE"):
        """
        Initializes the Tool Gateway with a specific security mode.

        Args:
            mode (str): Either 'SECURE' or 'INSECURE'. Default is 'SECURE'.
        """
        if mode.upper() not in ["SECURE", "INSECURE"]:
            raise ValueError("Gateway mode must be 'SECURE' or 'INSECURE'")
        self.mode = mode.upper()

    def execute_tool(self, context: dict, tool_name: str, arguments: dict):
        """
        Executes a tool on behalf of a user and agent, maintaining caller context.

        Args:
            context (dict): Dictionary with "user_id" and "agent_id".
            tool_name (str): The name of the tool to run.
            arguments (dict): The arguments for the tool.

        Returns:
            The results from the tool execution.
        """
        user_id = context.get("user_id")
        agent_id = context.get("agent_id", "banking-assistant")

        if not user_id:
            raise ValueError("Caller Context Error: 'user_id' is required.")

        # Log gateway dispatch (audit detail is emitted by the tool itself)
        logger.info(
            "[AUDIT LOG] [Agent ID: %s] [User ID: %s] "
            "Invoking Tool: '%s' in '%s' mode with Arguments: %s",
            agent_id, user_id, tool_name, self.mode, arguments,
        )

        if tool_name == "get_account_summary":
            return get_account_summary(
                agent_id=agent_id,
                user_id=user_id,
                security_mode=self.mode,
            )

        elif tool_name == "get_transaction_history":
            account_id = arguments.get("account_id")
            if not account_id:
                raise ValueError("Missing 'account_id' in tool arguments.")

            return get_transaction_history(
                agent_id=agent_id,
                user_id=user_id,
                account_id=str(account_id),
                security_mode=self.mode,
            )

        else:
            raise ValueError(f"Unknown tool: '{tool_name}'")
