"""
Security Validation Tests for the Agent Security Lab.
These tests run against the live Legacy Netbanking application.

user1 owns ACC1001 (account id 2) and ACC1002 (account id 3).
user2 owns ACC2001 (account id 4).

Demonstrates insecure BOLA (Broken Object Level Authorization) behavior
and secure authorization enforcement.
"""

import os
import sys
import unittest

# Ensure the parent directory is in sys.path so we can import packages correctly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.banking_tools as banking_tools
from agent.mock_agent import MockBankingAgent
from gateway.tool_gateway import ToolGateway


AGENT_ID = "banking-assistant"
USER_ID  = "user1"
PASSWORD = "password1"


class TestGatewaySecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Authenticate once against the live application before all tests."""
        cls.agent_id = AGENT_ID
        cls.agent = MockBankingAgent(agent_id=cls.agent_id)
        cls.gateway_insecure = ToolGateway(mode="INSECURE")
        cls.gateway_secure   = ToolGateway(mode="SECURE")

        success = banking_tools.login(USER_ID, PASSWORD)
        if not success:
            raise RuntimeError(
                "Could not authenticate with Legacy Netbanking. "
                "Ensure the application is running on localhost:8080."
            )

    def test_user1_retrieves_own_transactions_secure(self):
        """
        1. user1 can retrieve their own transactions.
        SECURE mode, account ACC1001 (id 2).  Should succeed and return transactions.
        """
        user_id = USER_ID
        request = "Show my transactions for account ACC1001"

        decision = self.agent.decide_tool(user_id, request)
        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "ACC1001")

        context = {"user_id": user_id, "agent_id": self.agent_id}
        result = self.gateway_secure.execute_tool(context, decision["tool_name"], decision["arguments"])

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        for tx in result:
            self.assertTrue(
                tx["from_account"] == "ACC1001" or tx["to_account"] == "ACC1001",
                f"Unexpected transaction not involving ACC1001: {tx}",
            )

    def test_user1_retrieves_foreign_account_insecure_bola(self):
        """
        2. INSECURE mode: user1 retrieves account 4 (ACC2001 – belongs to user2).
        This is the controlled Broken Object Level Authorization (BOLA) failure.
        """
        user_id = USER_ID
        request = "Show transactions for account 4"  # account 4 = ACC2001 (user2)

        decision = self.agent.decide_tool(user_id, request)
        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "4")

        context = {"user_id": user_id, "agent_id": self.agent_id}
        result = self.gateway_insecure.execute_tool(context, decision["tool_name"], decision["arguments"])

        # user1 successfully received user2's transactions (BOLA demonstrated)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        acc2001_involved = any(
            tx["from_account"] == "ACC2001" or tx["to_account"] == "ACC2001"
            for tx in result
        )
        self.assertTrue(acc2001_involved, f"Expected ACC2001 in BOLA result: {result}")

    def test_user1_retrieves_foreign_account_secure_prevented(self):
        """
        3. SECURE mode: user1 cannot retrieve account 4 (belongs to user2).
        The gateway must raise PermissionError before calling the legacy application.
        """
        user_id = USER_ID
        request = "Show transactions for account 4"  # account 4 = ACC2001 (user2)

        decision = self.agent.decide_tool(user_id, request)
        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "4")

        context = {"user_id": user_id, "agent_id": self.agent_id}

        with self.assertRaises(PermissionError) as context_manager:
            self.gateway_secure.execute_tool(context, decision["tool_name"], decision["arguments"])

        error_text = str(context_manager.exception)
        self.assertIn("Access Denied", error_text)
        self.assertIn(user_id, error_text)

    def test_logging_agent_and_user_identities(self):
        """
        4. The agent identity and user identity are logged for every tool call.
        We capture logs to verify both 'banking-assistant' and 'user1' are included.
        """
        user_id = USER_ID
        request = "Give me an account summary"

        decision = self.agent.decide_tool(user_id, request)
        self.assertEqual(decision["tool_name"], "get_account_summary")

        context = {"user_id": user_id, "agent_id": self.agent_id}

        with self.assertLogs("agent-security-lab.gateway", level="INFO") as captured_logs:
            self.gateway_secure.execute_tool(context, decision["tool_name"], decision["arguments"])

        audit_found = False
        for log in captured_logs.output:
            if "[AUDIT LOG]" in log:
                audit_found = True
                self.assertIn(f"Agent ID: {self.agent_id}", log)
                self.assertIn(f"User ID: {user_id}", log)
                self.assertIn("get_account_summary", log)

        self.assertTrue(audit_found, "Audit log was not captured or formatted incorrectly.")


if __name__ == "__main__":
    unittest.main()
