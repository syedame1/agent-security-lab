"""
Deterministic Mock Banking Agent.
Decides which tool to invoke using simple deterministic rule-based logic.
Do NOT use an LLM.
"""

import re
import logging

logger = logging.getLogger("agent-security-lab.agent")


class MockBankingAgent:
    def __init__(self, agent_id: str = "banking-assistant"):
        self.agent_id = agent_id

    def _detect_account_id(self, request: str) -> str:
        """
        Parses account_id from the user request using string matching and regex.
        Supports:
          - Named account numbers: ACC1001, ACC1002, ACC2001, ADMIN001, etc.
          - Bare numeric account ids used by the legacy app's URL parameter
            (e.g. "account 2", "accountId=4", "account id 4").
        Returns the matched token as a string, or None.
        """
        request_upper = request.upper()

        # Explicit search for known named account identifiers
        known_accounts = ["ACC1001", "ACC1002", "ACC2001", "ADMIN001", "ACC-ALICE-01", "ACC-BOB-01"]
        for acc in known_accounts:
            if acc in request_upper:
                return acc

        # Generic alphanumeric named account pattern
        match = re.search(r'\b(ACC\d+|ADMIN\d+|ACC-[A-Z]+-\d+)\b', request_upper)
        if match:
            return match.group(1)

        # Bare numeric id – matches phrases like "account 4", "accountId=4",
        # "account id 4", "id=2", etc.
        match = re.search(
            r'(?:account[\s_-]*(?:id)?[\s=]*|accountid[\s=]*|id[\s=]*)(\d+)',
            request,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        return None

    def decide_tool(self, user_id: str, request: str) -> dict:
        """
        Accepts user_id and raw request text.
        Decides which tool to invoke using simple deterministic keyword rules.
        
        Returns:
            dict containing:
                "tool_name": str
                "arguments": dict
        """
        req_lower = request.lower()
        logger.info(f"Agent '{self.agent_id}' processing request for user '{user_id}': '{request}'")
        
        # Detect transaction keywords
        tx_keywords = ["transaction", "transactions", "history", "statement", "payment", "payments", "ledger", "tx"]
        is_tx_req = any(keyword in req_lower for keyword in tx_keywords)
        
        if is_tx_req:
            account_id = self._detect_account_id(request)
            if not account_id:
                logger.error(f"Agent '{self.agent_id}' could not extract account_id from request: '{request}'")
                raise ValueError("Could not determine account ID from transaction history request.")
            
            logger.info(f"Agent '{self.agent_id}' determined tool: 'get_transaction_history' with account_id='{account_id}'")
            return {
                "tool_name": "get_transaction_history",
                "arguments": {
                    "account_id": account_id
                }
            }
        
        # Default or summary keywords
        logger.info(f"Agent '{self.agent_id}' determined tool: 'get_account_summary' for user_id='{user_id}'")
        return {
            "tool_name": "get_account_summary",
            "arguments": {
                "user_id": user_id
            }
        }
