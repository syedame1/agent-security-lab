"""
Integration tests for the Agent Security Lab against the live
Legacy Netbanking application (http://localhost:8080/legacy-netbanking).

Prerequisites
-------------
The Legacy Netbanking application must be running on localhost:8080.
These tests make real HTTP calls; they do NOT use mocks.

Test matrix
-----------
TEST 1  user1 → ACC1001 / account 2 → SECURE  → ALLOWED  → real transactions returned
TEST 2  user1 → account 4           → SECURE  → BLOCKED  → legacy app never called
TEST 3  user1 → account 4           → INSECURE → ALLOWED  → ACC2001 data returned (BOLA)

Credentials
-----------
agent_id = "banking-assistant"
user_id  = "user1"
password = "password1"
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


class TestLiveIntegration(unittest.TestCase):
    """
    Integration tests that call the real Legacy Netbanking application.
    A single login is shared across all three tests via setUpClass.
    """

    @classmethod
    def setUpClass(cls):
        """Authenticate once before all tests in this class."""
        cls.agent = MockBankingAgent(agent_id=AGENT_ID)
        cls.gateway_secure   = ToolGateway(mode="SECURE")
        cls.gateway_insecure = ToolGateway(mode="INSECURE")
        cls.context = {"user_id": USER_ID, "agent_id": AGENT_ID}

        success = banking_tools.login(USER_ID, PASSWORD)
        if not success:
            raise RuntimeError(
                "Could not authenticate with Legacy Netbanking. "
                "Ensure the application is running on localhost:8080."
            )

    # ------------------------------------------------------------------
    # TEST 1
    # user1 → ACC1001 / account 2 → SECURE → ALLOWED
    # → real Legacy Netbanking → transactions returned
    # ------------------------------------------------------------------
    def test_1_secure_user1_own_account_allowed(self):
        """
        TEST 1: user1 requests account 2 (ACC1001 – their own account) via
        SECURE mode.  The gateway must allow the request, call the legacy
        application, and return real transaction rows that involve ACC1001.
        """
        request = "Show my transactions for account 2"
        decision = self.agent.decide_tool(USER_ID, request)

        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "2")

        result = self.gateway_secure.execute_tool(
            self.context, decision["tool_name"], decision["arguments"]
        )

        # Must be a non-empty list from the real application
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, "Expected at least one transaction for ACC1001")

        # Every returned row must involve ACC1001
        for tx in result:
            self.assertTrue(
                tx["from_account"] == "ACC1001" or tx["to_account"] == "ACC1001",
                f"Unexpected transaction not involving ACC1001: {tx}",
            )

    # ------------------------------------------------------------------
    # TEST 2
    # user1 → account 4 → SECURE → BLOCKED before legacy app is called
    # ------------------------------------------------------------------
    def test_2_secure_user1_foreign_account_blocked(self):
        """
        TEST 2: user1 requests account 4 (ACC2001 – belongs to user2) via
        SECURE mode.  The gateway must raise PermissionError and must NOT
        call the legacy application.
        """
        request = "Show transactions for account 4"
        decision = self.agent.decide_tool(USER_ID, request)

        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "4")

        with self.assertRaises(PermissionError) as cm:
            self.gateway_secure.execute_tool(
                self.context, decision["tool_name"], decision["arguments"]
            )

        error_text = str(cm.exception)
        self.assertIn("Access Denied", error_text)
        self.assertIn(USER_ID, error_text)
        # Confirm the denial message references account 4
        self.assertIn("4", error_text)

    # ------------------------------------------------------------------
    # TEST 3
    # user1 → account 4 → INSECURE → request reaches Legacy Netbanking
    # → response contains ACC2001 transaction data (BOLA demonstrated)
    # ------------------------------------------------------------------
    def test_3_insecure_user1_foreign_account_bola(self):
        """
        TEST 3: user1 requests account 4 (ACC2001) via INSECURE mode.
        The request must reach the Legacy Netbanking application and the
        response must contain ACC2001 transaction data belonging to user2.
        This demonstrates the Broken Object Level Authorization (BOLA) flaw.
        """
        request = "Show transactions for account 4"
        decision = self.agent.decide_tool(USER_ID, request)

        self.assertEqual(decision["tool_name"], "get_transaction_history")
        self.assertEqual(decision["arguments"]["account_id"], "4")

        result = self.gateway_insecure.execute_tool(
            self.context, decision["tool_name"], decision["arguments"]
        )

        # Legacy app returns rows; at least one must involve ACC2001
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, "Expected ACC2001 transactions from the legacy app")

        acc2001_found = any(
            tx["from_account"] == "ACC2001" or tx["to_account"] == "ACC2001"
            for tx in result
        )
        self.assertTrue(
            acc2001_found,
            f"Expected ACC2001 in BOLA response but got: {result}",
        )


if __name__ == "__main__":
    unittest.main()
