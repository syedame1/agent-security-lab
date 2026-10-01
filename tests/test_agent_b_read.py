"""
Phase 2 Step 3 — Agent B Read Capability Tests.

Test coverage
-------------
A. Agent B can read an existing package.
B. Agent B cannot publish.
C. Agent A cannot use read_package (unless explicitly authorized).
D. Agent B cannot read from an unauthorized repository.
E. Denied read operations never make the HTTP request.
F. Missing package returns a clean not-found/error result.
G. Package content is returned as inert data.
H. Audit records are generated for ALLOW and DENY.
I. End-to-end chain: Agent A publishes → package exists → Agent B reads
   → content matches exactly.

All tests are self-contained and do NOT require the Legacy Netbanking
application or Tomcat.
"""

import shutil
import tempfile
import threading
import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from fake_artifactory.service import create_server
from agent.publisher_agent import BankingPublisherAgent
from agent.reader_agent import BankingReaderAgent
from gateway.authorization_policy import check_authorization, REPOSITORY_NAME
from gateway.publish_gateway import PublishGateway
from gateway.read_gateway import ReadGateway
from tools.read_tool import read_package as _read_package_tool, DEFAULT_ARTIFACTORY_URL


# ---------------------------------------------------------------------------
# Shared test fixture — one embedded Fake Artifactory for the whole module
# ---------------------------------------------------------------------------

class _ArtifactoryFixture:
    PORT = 8897  # distinct port — avoids clashes with other test modules

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server = create_server(
            host="127.0.0.1",
            port=self.PORT,
            storage_dir=self.temp_dir,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.PORT}"

    def teardown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)


_fixture: _ArtifactoryFixture | None = None


def setUpModule():
    global _fixture
    _fixture = _ArtifactoryFixture()


def tearDownModule():
    if _fixture:
        _fixture.teardown()


# ---------------------------------------------------------------------------
# Helper: publish directly via HTTP (bypasses gateway, for test setup only)
# ---------------------------------------------------------------------------

def _direct_publish(base_url: str, package_name: str, content: str) -> None:
    """Publish a package directly to the Fake Artifactory (test setup helper)."""
    resp = requests.post(
        f"{base_url}/packages/{package_name}",
        json={"content": content},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert resp.status_code == 201, f"Setup publish failed: {resp.status_code} {resp.text}"


# ===========================================================================
# A — Agent B can read an existing package
# ===========================================================================

class TestAgentBCanRead(unittest.TestCase):
    """Test A: Agent B can read a package that exists in the repository."""

    def setUp(self):
        self.gateway = ReadGateway(artifactory_url=_fixture.base_url)
        _direct_publish(_fixture.base_url, "test-read-pkg", "hello from Agent A")

    def test_agent_b_can_read_existing_package(self):
        context = {"agent_id": "banking-reader"}
        result = self.gateway.execute_tool(
            context, "read_package", {"package_name": "test-read-pkg"}
        )
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["package"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["package"]["name"], "test-read-pkg")
        self.assertEqual(result["package"]["content"], "hello from Agent A")
        self.assertIn("published_at", result["package"])

    def test_agent_b_reader_agent_decide_tool(self):
        agent = BankingReaderAgent()
        self.assertEqual(agent.agent_id, "banking-reader")
        decision = agent.decide_tool("my-pkg")
        self.assertEqual(decision["tool_name"], "read_package")
        self.assertEqual(decision["arguments"]["package_name"], "my-pkg")


# ===========================================================================
# B — Agent B cannot publish
# ===========================================================================

class TestAgentBCannotPublish(unittest.TestCase):
    """Test B: banking-reader is not authorized to invoke publish_package."""

    def setUp(self):
        self.publish_gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_agent_b_cannot_publish(self):
        context = {"agent_id": "banking-reader"}
        with self.assertRaises(PermissionError) as cm:
            self.publish_gateway.execute_tool(
                context,
                "publish_package",
                {"package_name": "reader-try", "message": "should be denied"},
            )
        self.assertIn("banking-reader", str(cm.exception))
        self.assertIn("publish_package", str(cm.exception))

    def test_agent_b_publish_policy_is_deny(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_agent_b_publish_never_reaches_artifactory(self):
        """Confirm the package is NOT stored when banking-reader tries to publish."""
        context = {"agent_id": "banking-reader"}
        try:
            self.publish_gateway.execute_tool(
                context,
                "publish_package",
                {"package_name": "b-blocked-pkg", "message": "never stored"},
            )
        except PermissionError:
            pass

        resp = requests.get(
            f"{_fixture.base_url}/packages/b-blocked-pkg", timeout=5
        )
        self.assertEqual(resp.status_code, 404)


# ===========================================================================
# C — Agent A cannot use read_package
# ===========================================================================

class TestAgentACannotRead(unittest.TestCase):
    """Test C: banking-publisher is not authorized to invoke read_package."""

    def setUp(self):
        self.read_gateway = ReadGateway(artifactory_url=_fixture.base_url)

    def test_agent_a_cannot_read(self):
        context = {"agent_id": "banking-publisher"}
        with self.assertRaises(PermissionError) as cm:
            self.read_gateway.execute_tool(
                context,
                "read_package",
                {"package_name": "any-pkg"},
            )
        self.assertIn("banking-publisher", str(cm.exception))
        self.assertIn("read_package", str(cm.exception))

    def test_agent_a_read_policy_is_deny(self):
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")


# ===========================================================================
# D — Agent B cannot read from an unauthorized repository
# ===========================================================================

class TestAgentBUnauthorizedRepository(unittest.TestCase):
    """Test D: banking-reader is denied on any repository other than fake-artifactory-local."""

    def test_banking_reader_denied_unknown_repo(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository="some-other-repo",
        )
        self.assertEqual(result["decision"], "DENY")

    def test_banking_reader_denied_empty_repo(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository="",
        )
        self.assertEqual(result["decision"], "DENY")

    def test_banking_reader_allowed_only_on_known_repo(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "ALLOW")


# ===========================================================================
# E — Denied read operations never make the HTTP request
# ===========================================================================

class TestDeniedReadNeverCallsHTTP(unittest.TestCase):
    """Test E: A DENY decision means the Fake Artifactory is NEVER contacted."""

    def setUp(self):
        self.read_gateway = ReadGateway(artifactory_url=_fixture.base_url)

    def test_denied_agent_http_never_called(self):
        """Mock requests.get to confirm it is NOT called on a DENY."""
        with patch("tools.read_tool.requests.get") as mock_get:
            context = {"agent_id": "rogue-agent"}
            with self.assertRaises(PermissionError):
                self.read_gateway.execute_tool(
                    context, "read_package", {"package_name": "any-pkg"}
                )
            mock_get.assert_not_called()

    def test_banking_reader_publish_http_never_called(self):
        """Mock requests.post to confirm it is NOT called when Agent B tries to publish."""
        publish_gateway = PublishGateway(artifactory_url=_fixture.base_url)
        with patch("tools.publish_tool.requests.post") as mock_post:
            context = {"agent_id": "banking-reader"}
            with self.assertRaises(PermissionError):
                publish_gateway.execute_tool(
                    context,
                    "publish_package",
                    {"package_name": "never-pkg", "message": "never"},
                )
            mock_post.assert_not_called()


# ===========================================================================
# F — Missing package returns a clean not-found/error result
# ===========================================================================

class TestMissingPackageCleanResult(unittest.TestCase):
    """Test F: Reading a non-existent package returns a structured error, not an exception."""

    def setUp(self):
        self.gateway = ReadGateway(artifactory_url=_fixture.base_url)

    def test_missing_package_returns_error_dict(self):
        context = {"agent_id": "banking-reader"}
        result = self.gateway.execute_tool(
            context, "read_package", {"package_name": "does-not-exist-xyz"}
        )
        self.assertFalse(result["success"])
        self.assertIsNone(result["package"])
        self.assertIsNotNone(result["error"])
        self.assertIn("not found", result["error"].lower())

    def test_missing_package_does_not_raise(self):
        """A 404 from Artifactory should NOT raise an exception."""
        context = {"agent_id": "banking-reader"}
        try:
            result = self.gateway.execute_tool(
                context, "read_package", {"package_name": "absolutely-not-there"}
            )
            self.assertFalse(result["success"])
        except Exception as exc:  # noqa: BLE001
            self.fail(f"Unexpected exception for missing package: {exc}")

    def test_invalid_package_name_raises_value_error(self):
        """Invalid package name should raise ValueError before any HTTP call."""
        with self.assertRaises(ValueError):
            _read_package_tool(
                agent_id="banking-reader",
                package_name="../../etc/passwd",
                artifactory_url=_fixture.base_url,
            )


# ===========================================================================
# G — Package content is returned as inert data
# ===========================================================================

class TestContentIsInertData(unittest.TestCase):
    """Test G: Package content is always returned as a plain string — never executed."""

    def setUp(self):
        self.gateway = ReadGateway(artifactory_url=_fixture.base_url)
        # Publish packages with potentially code-like content
        _direct_publish(
            _fixture.base_url, "code-like-pkg", "import os; os.system('echo pwned')"
        )
        _direct_publish(
            _fixture.base_url, "json-msg-pkg", '{"message": "hello from Agent A"}'
        )
        _direct_publish(
            _fixture.base_url, "plain-msg-pkg", "hello from Agent A"
        )

    def test_code_string_is_returned_not_executed(self):
        context = {"agent_id": "banking-reader"}
        result = self.gateway.execute_tool(
            context, "read_package", {"package_name": "code-like-pkg"}
        )
        self.assertTrue(result["success"])
        # Content is the raw string — not executed
        self.assertIsInstance(result["package"]["content"], str)
        self.assertEqual(
            result["package"]["content"],
            "import os; os.system('echo pwned')",
        )

    def test_json_string_is_not_parsed(self):
        context = {"agent_id": "banking-reader"}
        result = self.gateway.execute_tool(
            context, "read_package", {"package_name": "json-msg-pkg"}
        )
        self.assertTrue(result["success"])
        # Content must be a plain str, not a parsed dict
        self.assertIsInstance(result["package"]["content"], str)

    def test_plain_message_returned_verbatim(self):
        context = {"agent_id": "banking-reader"}
        result = self.gateway.execute_tool(
            context, "read_package", {"package_name": "plain-msg-pkg"}
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["package"]["content"], "hello from Agent A")


# ===========================================================================
# H — Audit records generated for ALLOW and DENY
# ===========================================================================

class TestAuditLogging(unittest.TestCase):
    """Test H: Structured audit log lines are emitted for both ALLOW and DENY."""

    def setUp(self):
        self.gateway = ReadGateway(artifactory_url=_fixture.base_url)
        _direct_publish(_fixture.base_url, "audit-test-pkg", "audit content")

    def test_audit_record_on_allow(self):
        context = {"agent_id": "banking-reader", "user_id": "test-user"}
        with self.assertLogs("agent-security-lab.tools", level="INFO") as captured:
            self.gateway.execute_tool(
                context, "read_package", {"package_name": "audit-test-pkg"}
            )

        audit_lines = [l for l in captured.output if "[AUDIT]" in l]
        self.assertGreater(len(audit_lines), 0, "No [AUDIT] line found for ALLOW read")

        line = audit_lines[0]
        self.assertIn("banking-reader", line)
        self.assertIn("read_package", line)
        self.assertIn("read", line)
        self.assertIn(REPOSITORY_NAME, line)
        self.assertIn("audit-test-pkg", line)
        self.assertIn("ALLOWED", line)
        self.assertIn("SUCCESS", line)
        # Ensure no secrets are present
        self.assertNotIn("password", line.lower())
        self.assertNotIn("token", line.lower())
        self.assertNotIn("cookie", line.lower())

    def test_audit_record_on_deny(self):
        """A DENY should emit an [AUTHZ] log line from the authorization policy."""
        context = {"agent_id": "rogue-agent"}
        with self.assertLogs("agent-security-lab.authorization", level="INFO") as captured:
            with self.assertRaises(PermissionError):
                self.gateway.execute_tool(
                    context, "read_package", {"package_name": "audit-test-pkg"}
                )

        authz_lines = [l for l in captured.output if "[AUTHZ]" in l]
        self.assertGreater(len(authz_lines), 0, "No [AUTHZ] line found for DENY read")

        line = authz_lines[0]
        self.assertIn("rogue-agent", line)
        self.assertIn("read_package", line)
        self.assertIn("DENY", line)

    def test_gateway_audit_log_on_dispatch(self):
        """The gateway itself emits an [AUDIT LOG] before the authorization check."""
        context = {"agent_id": "banking-reader", "user_id": "test-user"}
        with self.assertLogs("agent-security-lab.gateway", level="INFO") as captured:
            self.gateway.execute_tool(
                context, "read_package", {"package_name": "audit-test-pkg"}
            )

        gateway_audit = [l for l in captured.output if "[AUDIT LOG]" in l]
        self.assertGreater(len(gateway_audit), 0)
        line = gateway_audit[0]
        self.assertIn("banking-reader", line)
        self.assertIn("test-user", line)
        self.assertIn("read_package", line)

    def test_deny_audit_gateway_log(self):
        """The gateway emits a warning log on DENY before raising PermissionError."""
        context = {"agent_id": "rogue-reader"}
        with self.assertLogs("agent-security-lab.gateway", level="WARNING") as captured:
            with self.assertRaises(PermissionError):
                self.gateway.execute_tool(
                    context, "read_package", {"package_name": "audit-test-pkg"}
                )

        deny_lines = [l for l in captured.output if "AUTHZ DENIED" in l]
        self.assertGreater(len(deny_lines), 0)
        line = deny_lines[0]
        self.assertIn("rogue-reader", line)
        self.assertIn("Fake Artifactory was NOT called", line)


# ===========================================================================
# I — End-to-end chain: Agent A publishes → Agent B reads → content matches
# ===========================================================================

class TestEndToEndAgentAToAgentB(unittest.TestCase):
    """
    Test I: Full A → repository → B chain.

    Agent A publishes a message.  Agent B reads it back.
    The content received by Agent B must exactly match what Agent A published.
    Agent A and Agent B do not communicate directly.
    """

    def setUp(self):
        self.agent_a = BankingPublisherAgent()
        self.agent_b = BankingReaderAgent()
        self.publish_gateway = PublishGateway(artifactory_url=_fixture.base_url)
        self.read_gateway = ReadGateway(artifactory_url=_fixture.base_url)

    def test_end_to_end_chain(self):
        package_name = "e2e-agent-message"
        original_content = "hello from Agent A"

        # --- Agent A publishes ---
        decision_a = self.agent_a.decide_tool(package_name, original_content)
        self.assertEqual(decision_a["tool_name"], "publish_package")

        context_a = {"agent_id": self.agent_a.agent_id}
        publish_result = self.publish_gateway.execute_tool(
            context_a, decision_a["tool_name"], decision_a["arguments"]
        )
        self.assertTrue(publish_result["success"], f"Publish failed: {publish_result['error']}")

        # --- Package now exists in the shared repository ---
        verify_resp = requests.get(
            f"{_fixture.base_url}/packages/{package_name}", timeout=5
        )
        self.assertEqual(verify_resp.status_code, 200)

        # --- Agent B reads ---
        decision_b = self.agent_b.decide_tool(package_name)
        self.assertEqual(decision_b["tool_name"], "read_package")

        context_b = {"agent_id": self.agent_b.agent_id}
        read_result = self.read_gateway.execute_tool(
            context_b, decision_b["tool_name"], decision_b["arguments"]
        )
        self.assertTrue(read_result["success"], f"Read failed: {read_result['error']}")

        # --- Content received by Agent B must exactly match what Agent A published ---
        received = read_result["package"]["content"]
        self.assertEqual(
            received,
            original_content,
            f"Content mismatch: got '{received}', expected '{original_content}'",
        )

    def test_agents_do_not_call_each_other_directly(self):
        """Structural: agent_a and agent_b have no reference to each other."""
        agent_a = BankingPublisherAgent()
        agent_b = BankingReaderAgent()
        # Neither agent exposes a method to call the other directly
        self.assertFalse(
            hasattr(agent_a, "reader") or hasattr(agent_a, "agent_b"),
            "Agent A should not hold a reference to Agent B",
        )
        self.assertFalse(
            hasattr(agent_b, "publisher") or hasattr(agent_b, "agent_a"),
            "Agent B should not hold a reference to Agent A",
        )

    def test_agent_b_cannot_publish_via_read_gateway(self):
        """Agent B's only gateway is ReadGateway — it has no path to publish."""
        context_b = {"agent_id": self.agent_b.agent_id}
        with self.assertRaises(PermissionError):
            self.read_gateway.execute_tool(
                context_b,
                "publish_package",  # unknown tool for ReadGateway → DENY
                {"package_name": "inject-pkg", "message": "should not be stored"},
            )

    def test_end_to_end_with_json_like_content(self):
        """Content that looks like JSON is returned verbatim as a string, not parsed."""
        package_name = "e2e-json-msg"
        original_content = '{"message": "hello from Agent A"}'

        # Agent A publishes JSON-like content
        decision_a = self.agent_a.decide_tool(package_name, original_content)
        context_a = {"agent_id": self.agent_a.agent_id}
        publish_result = self.publish_gateway.execute_tool(
            context_a, decision_a["tool_name"], decision_a["arguments"]
        )
        self.assertTrue(publish_result["success"])

        # Agent B reads
        decision_b = self.agent_b.decide_tool(package_name)
        context_b = {"agent_id": self.agent_b.agent_id}
        read_result = self.read_gateway.execute_tool(
            context_b, decision_b["tool_name"], decision_b["arguments"]
        )
        self.assertTrue(read_result["success"])

        received = read_result["package"]["content"]
        self.assertEqual(received, original_content)
        # Must be a str, not a dict
        self.assertIsInstance(received, str)


# ===========================================================================
# Additional: Authorization policy completeness checks
# ===========================================================================

class TestAuthorizationPolicyCompleteness(unittest.TestCase):
    """Verify all required ALLOW/DENY combinations in the policy table."""

    def test_banking_publisher_publish_allowed(self):
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "ALLOW")

    def test_banking_reader_read_allowed(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "ALLOW")

    def test_banking_reader_publish_denied(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_banking_publisher_read_denied(self):
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_banking_reader_read_unknown_repo_denied(self):
        result = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository="unknown-repo",
        )
        self.assertEqual(result["decision"], "DENY")

    def test_unknown_agent_read_denied(self):
        result = check_authorization(
            agent_id="unknown-agent",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")


# ===========================================================================
# Additional: BankingReaderAgent unit tests
# ===========================================================================

class TestBankingReaderAgent(unittest.TestCase):
    """Unit tests for the BankingReaderAgent class."""

    def setUp(self):
        self.agent = BankingReaderAgent()

    def test_agent_id_is_banking_reader(self):
        self.assertEqual(self.agent.agent_id, "banking-reader")

    def test_decide_tool_returns_read_package(self):
        decision = self.agent.decide_tool("some-package")
        self.assertEqual(decision["tool_name"], "read_package")
        self.assertEqual(decision["arguments"]["package_name"], "some-package")

    def test_decide_tool_preserves_package_name(self):
        decision = self.agent.decide_tool("my-special-pkg")
        self.assertEqual(decision["arguments"]["package_name"], "my-special-pkg")


# ===========================================================================
# Additional: ReadGateway error handling
# ===========================================================================

class TestReadGatewayErrorHandling(unittest.TestCase):

    def test_missing_agent_id_raises_value_error(self):
        gateway = ReadGateway(artifactory_url=_fixture.base_url)
        with self.assertRaises(ValueError) as cm:
            gateway.execute_tool({}, "read_package", {"package_name": "any"})
        self.assertIn("agent_id", str(cm.exception))

    def test_unknown_tool_raises_after_authz(self):
        """An authorized agent requesting an unknown tool raises ValueError."""
        gateway = ReadGateway(artifactory_url=_fixture.base_url)
        # Patch authz to return ALLOW so we reach the tool dispatch
        with patch(
            "gateway.read_gateway.check_authorization",
            return_value={
                "decision": "ALLOW",
                "reason": "test",
                "agent_id": "banking-reader",
                "tool_name": "nonexistent_tool",
                "target_repository": REPOSITORY_NAME,
            },
        ):
            with self.assertRaises(ValueError) as cm:
                gateway.execute_tool(
                    {"agent_id": "banking-reader"},
                    "nonexistent_tool",
                    {"package_name": "any"},
                )
        self.assertIn("nonexistent_tool", str(cm.exception))

    def test_external_url_raises_value_error(self):
        """read_package tool must refuse external URLs."""
        from tools.read_tool import read_package as rp
        with self.assertRaises(ValueError) as cm:
            rp(
                agent_id="banking-reader",
                package_name="pkg",
                artifactory_url="http://evil.example.com",
            )
        self.assertIn("non-localhost", str(cm.exception))

    def test_connection_error_returns_failure_dict(self):
        """If Artifactory is unreachable, the tool returns a failure dict, not exception."""
        from tools.read_tool import read_package as rp
        with patch("tools.read_tool.requests.get") as mock_get:
            import requests as req
            mock_get.side_effect = req.exceptions.ConnectionError("refused")
            result = rp(
                agent_id="banking-reader",
                package_name="some-pkg",
                artifactory_url="http://127.0.0.1:9999",
            )
        self.assertFalse(result["success"])
        self.assertIn("Connection error", result["error"])


if __name__ == "__main__":
    unittest.main()
