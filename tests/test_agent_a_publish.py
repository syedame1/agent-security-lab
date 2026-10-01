"""
Tests for Phase 2 Step 2 — Agent A Package Publishing Tool.

Coverage
--------
a. Authorized Agent A can publish.
b. Unauthorized agent is denied.
c. Denied operation never reaches Fake Artifactory.
d. Valid package is persisted (end-to-end with live in-process server).
e. Invalid package names are rejected.
f. Tool errors are handled cleanly (connection failure).
g. Audit records are generated for both ALLOW and DENY.
h. Authorization policy table is correct (unit test).
i. publish_tool refuses external URLs.
j. BankingPublisherAgent produces correct tool decisions.
"""

import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

# Ensure the agent-security-lab root is on sys.path regardless of how pytest
# or unittest discovers the file.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.publisher_agent import BankingPublisherAgent
from fake_artifactory.service import create_server
from gateway.authorization_policy import check_authorization, REPOSITORY_NAME
from gateway.publish_gateway import PublishGateway
from tools.publish_tool import (
    DEFAULT_ARTIFACTORY_URL,
    _is_valid_package_name,
    publish_package,
)


# ---------------------------------------------------------------------------
# Shared in-process Fake Artifactory server fixture
# ---------------------------------------------------------------------------

class _ArtifactoryFixture:
    """Starts an in-process Fake Artifactory on a free port for the test run."""

    PORT = 8898  # distinct port that avoids clashes with other test classes

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server = create_server(
            host="127.0.0.1", port=self.PORT, storage_dir=self.temp_dir
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


# Module-level fixture so all test classes share the same server process.
_fixture: _ArtifactoryFixture | None = None


def setUpModule():
    global _fixture
    _fixture = _ArtifactoryFixture()


def tearDownModule():
    if _fixture:
        _fixture.teardown()


# ---------------------------------------------------------------------------
# a. Authorization policy unit tests — (agent_id, tool_name, repository) triples
# ---------------------------------------------------------------------------

class TestAuthorizationPolicy(unittest.TestCase):
    """Unit tests for gateway/authorization_policy.py."""

    def test_banking_publisher_allowed_to_publish_package(self):
        """banking-publisher MUST be ALLOWED to invoke publish_package on fake-artifactory-local."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "ALLOW")

    def test_unknown_agent_denied_publish_package(self):
        """An agent not in the policy table must be DENIED."""
        result = check_authorization(
            agent_id="unknown-agent",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_banking_publisher_denied_unknown_tool(self):
        """banking-publisher must be DENIED for any tool not in the policy."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="get_account_summary",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_empty_agent_id_denied(self):
        """An empty agent_id must resolve to DENY."""
        result = check_authorization(
            agent_id="",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")

    def test_deny_result_includes_reason(self):
        """DENY results must include a non-empty reason string."""
        result = check_authorization(
            agent_id="rogue-agent",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertTrue(len(result["reason"]) > 0)

    def test_allow_result_includes_reason(self):
        """ALLOW results must include a non-empty reason string."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(len(result["reason"]) > 0)


# ---------------------------------------------------------------------------
# New: Repository-aware authorization tests (a–d from the correction spec)
# ---------------------------------------------------------------------------

class TestRepositoryAuthorizationPolicy(unittest.TestCase):
    """
    Verify the three-dimensional authorization model:
        (agent_id, tool_name, target_repository)

    a. banking-publisher + publish_package + fake-artifactory-local = ALLOW
    b. rogue-agent       + publish_package + fake-artifactory-local = DENY
    c. banking-publisher + publish_package + unknown-repo           = DENY
    d. DENY means the HTTP call to the repository is never made.
    """

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_a_authorized_triple_is_allowed(self):
        """banking-publisher + publish_package + fake-artifactory-local = ALLOW."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository="fake-artifactory-local",
        )
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["target_repository"], "fake-artifactory-local")

    def test_b_rogue_agent_on_known_repo_is_denied(self):
        """rogue-agent + publish_package + fake-artifactory-local = DENY."""
        result = check_authorization(
            agent_id="rogue-agent",
            tool_name="publish_package",
            target_repository="fake-artifactory-local",
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("fake-artifactory-local", result["reason"])

    def test_c_authorized_agent_on_unknown_repo_is_denied(self):
        """banking-publisher + publish_package + unknown-repo = DENY."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository="unknown-repo",
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("unknown-repo", result["reason"])

    def test_c_authorized_agent_on_empty_repo_is_denied(self):
        """banking-publisher + publish_package + '' = DENY."""
        result = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository="",
        )
        self.assertEqual(result["decision"], "DENY")

    def test_d_deny_means_http_call_never_made(self):
        """
        When the gateway denies, requests.post must never be called —
        regardless of whether the agent or the repository caused the denial.
        """
        with patch("tools.publish_tool.requests.post") as mock_post:
            # b: rogue agent
            with self.assertRaises(PermissionError):
                self.gateway.execute_tool(
                    {"agent_id": "rogue-agent"},
                    "publish_package",
                    {"package_name": "evil-pkg", "message": "payload"},
                )
            mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# b + c. Unauthorized agent denied; Fake Artifactory NOT called
# ---------------------------------------------------------------------------

class TestUnauthorizedAgentDenied(unittest.TestCase):
    """
    An agent that is NOT in the policy must be denied by the gateway
    BEFORE the Fake Artifactory service is called.
    """

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_unauthorized_agent_raises_permission_error(self):
        """Gateway raises PermissionError for an agent with no ALLOW rule."""
        context = {"agent_id": "rogue-agent", "user_id": "attacker"}
        with self.assertRaises(PermissionError) as cm:
            self.gateway.execute_tool(
                context,
                "publish_package",
                {"package_name": "evil-pkg", "message": "bad content"},
            )
        self.assertIn("Authorization Denied", str(cm.exception))
        self.assertIn("rogue-agent", str(cm.exception))

    def test_fake_artifactory_not_called_on_deny(self):
        """
        The Fake Artifactory HTTP endpoint must never be reached when the
        gateway denies the request.  We patch publish_tool.requests.post to
        detect any HTTP call that would have been made.
        """
        with patch("tools.publish_tool.requests.post") as mock_post:
            context = {"agent_id": "rogue-agent"}
            with self.assertRaises(PermissionError):
                self.gateway.execute_tool(
                    context,
                    "publish_package",
                    {"package_name": "evil-pkg", "message": "bad content"},
                )
            mock_post.assert_not_called()

    def test_unauthorized_agent_denied_unknown_tool(self):
        """Any agent invoking an unknown tool is denied (deny-by-default)."""
        context = {"agent_id": "banking-publisher"}
        with self.assertRaises(PermissionError):
            self.gateway.execute_tool(
                context,
                "get_account_summary",
                {"user_id": "user1"},
            )


# ---------------------------------------------------------------------------
# a. Authorized Agent A can publish
# ---------------------------------------------------------------------------

class TestAuthorizedAgentCanPublish(unittest.TestCase):
    """banking-publisher is ALLOWED to publish; package arrives in Artifactory."""

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_banking_publisher_can_publish(self):
        """Authorized agent publishes successfully; gateway returns success dict."""
        context = {"agent_id": "banking-publisher", "user_id": "system"}
        result = self.gateway.execute_tool(
            context,
            "publish_package",
            {
                "package_name": "agent-message",
                "message": "hello from Agent A",
            },
        )
        self.assertTrue(result["success"], f"Expected success but got: {result}")
        self.assertIsNone(result["error"])
        pkg = result["package"]
        self.assertEqual(pkg["name"], "agent-message")
        self.assertEqual(pkg["content"], "hello from Agent A")

    def test_banking_publisher_can_publish_without_user_id(self):
        """The user_id field is optional; agent_id alone is sufficient."""
        context = {"agent_id": "banking-publisher"}
        result = self.gateway.execute_tool(
            context,
            "publish_package",
            {"package_name": "no-user-pkg", "message": "system publish"},
        )
        self.assertTrue(result["success"])


# ---------------------------------------------------------------------------
# d. Valid package is actually persisted
# ---------------------------------------------------------------------------

class TestPackagePersisted(unittest.TestCase):
    """Verify the package can be retrieved from Artifactory after publishing."""

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_published_package_retrievable(self):
        """After publish succeeds the package exists in the Fake Artifactory."""
        import requests as _requests

        context = {"agent_id": "banking-publisher", "user_id": "system"}
        pkg_name = "persisted-test-pkg"
        msg = "def get_auth_token():\n    return 'demo-token'"

        result = self.gateway.execute_tool(
            context,
            "publish_package",
            {"package_name": pkg_name, "message": msg},
        )
        self.assertTrue(result["success"])

        # Retrieve directly from Fake Artifactory
        resp = _requests.get(
            f"{_fixture.base_url}/packages/{pkg_name}", timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["name"], pkg_name)
        # Content is stored as text only — NEVER executed
        self.assertEqual(data["content"], msg)
        self.assertIn("published_at", data)


# ---------------------------------------------------------------------------
# e. Invalid package names are rejected
# ---------------------------------------------------------------------------

class TestInvalidPackageNameRejected(unittest.TestCase):
    """publish_tool must reject bad names BEFORE contacting Artifactory."""

    def test_empty_package_name_raises(self):
        with self.assertRaises(ValueError) as cm:
            publish_package(
                agent_id="banking-publisher",
                package_name="",
                message="content",
                artifactory_url=_fixture.base_url,
            )
        self.assertIn("Invalid package name", str(cm.exception))

    def test_path_traversal_name_raises(self):
        for bad in ["../etc/passwd", "../../root", "..\\evil"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    publish_package(
                        agent_id="banking-publisher",
                        package_name=bad,
                        message="payload",
                        artifactory_url=_fixture.base_url,
                    )

    def test_space_in_name_raises(self):
        with self.assertRaises(ValueError):
            publish_package(
                agent_id="banking-publisher",
                package_name="bad name",
                message="content",
                artifactory_url=_fixture.base_url,
            )

    def test_special_chars_raises(self):
        for bad in ["pkg$", "pkg!", "pkg@repo", "pkg;drop"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    publish_package(
                        agent_id="banking-publisher",
                        package_name=bad,
                        message="content",
                        artifactory_url=_fixture.base_url,
                    )

    def test_valid_names_pass_validation(self):
        for good in ["my-package", "pkg_v1", "banking-helper-v2", "simple"]:
            with self.subTest(good=good):
                self.assertTrue(_is_valid_package_name(good))


# ---------------------------------------------------------------------------
# f. Tool errors handled cleanly
# ---------------------------------------------------------------------------

class TestToolErrorHandling(unittest.TestCase):
    """Connection errors and Artifactory failures are returned, not raised."""

    def test_connection_error_returns_failure_dict(self):
        """A connection error to Artifactory returns success=False, not an exception."""
        with patch("tools.publish_tool.requests.post") as mock_post:
            import requests as _requests
            mock_post.side_effect = _requests.exceptions.ConnectionError("refused")
            result = publish_package(
                agent_id="banking-publisher",
                package_name="test-pkg",
                message="hello",
                artifactory_url="http://127.0.0.1:8081",
            )
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])
        self.assertIn("Connection error", result["error"])

    def test_external_url_raises_value_error(self):
        """publish_tool must refuse to contact a non-localhost URL."""
        with self.assertRaises(ValueError) as cm:
            publish_package(
                agent_id="banking-publisher",
                package_name="test-pkg",
                message="hello",
                artifactory_url="http://example.com",
            )
        self.assertIn("refuses to contact non-localhost", str(cm.exception))

    def test_gateway_missing_agent_id_raises(self):
        """Gateway raises ValueError if agent_id is absent from context."""
        gw = PublishGateway(artifactory_url=_fixture.base_url)
        with self.assertRaises(ValueError) as cm:
            gw.execute_tool({}, "publish_package", {"package_name": "p", "message": "m"})
        self.assertIn("agent_id", str(cm.exception))


# ---------------------------------------------------------------------------
# g. Audit records for ALLOW and DENY
# ---------------------------------------------------------------------------

class TestAuditLogging(unittest.TestCase):
    """
    Verify that structured [AUDIT] records are emitted for both ALLOW and DENY.
    Uses assertLogs to capture log output.
    """

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_audit_record_on_allow(self):
        """Successful publish generates an [AUDIT] line with key fields including
        repository and package_name as distinct fields."""
        context = {"agent_id": "banking-publisher", "user_id": "system"}
        with self.assertLogs("agent-security-lab.tools", level="INFO") as logs:
            self.gateway.execute_tool(
                context,
                "publish_package",
                {"package_name": "audit-allow-pkg", "message": "audit test"},
            )

        audit_lines = [l for l in logs.output if "[AUDIT]" in l]
        self.assertTrue(len(audit_lines) >= 1, "Expected at least one [AUDIT] line")

        line = audit_lines[-1]
        self.assertIn("banking-publisher", line)
        self.assertIn("publish_package", line)
        self.assertIn("ALLOWED", line)
        self.assertIn("SUCCESS", line)
        # repository and package_name are separate audit fields
        self.assertIn("repository=fake-artifactory-local", line)
        self.assertIn("package_name=audit-allow-pkg", line)
        # Secrets must never appear
        self.assertNotIn("password", line.lower())
        self.assertNotIn("cookie", line.lower())

    def test_audit_record_on_deny(self):
        """Denied request generates an [AUTHZ] line capturing the denial."""
        context = {"agent_id": "rogue-agent", "user_id": "attacker"}
        with self.assertLogs("agent-security-lab.authorization", level="INFO") as logs:
            with self.assertRaises(PermissionError):
                self.gateway.execute_tool(
                    context,
                    "publish_package",
                    {"package_name": "evil-pkg", "message": "malicious"},
                )

        authz_lines = [l for l in logs.output if "[AUTHZ]" in l]
        self.assertTrue(len(authz_lines) >= 1, "Expected at least one [AUTHZ] line")

        line = authz_lines[-1]
        self.assertIn("rogue-agent", line)
        self.assertIn("publish_package", line)
        self.assertIn("DENY", line)

    def test_gateway_audit_log_on_dispatch(self):
        """The gateway itself emits an [AUDIT LOG] line that names both the
        repository and the package separately."""
        context = {"agent_id": "banking-publisher", "user_id": "system"}
        with self.assertLogs("agent-security-lab.gateway", level="INFO") as logs:
            self.gateway.execute_tool(
                context,
                "publish_package",
                {"package_name": "gw-audit-pkg", "message": "gw audit test"},
            )

        gateway_lines = [l for l in logs.output if "[AUDIT LOG]" in l]
        self.assertTrue(len(gateway_lines) >= 1)
        line = gateway_lines[0]
        self.assertIn("banking-publisher", line)
        self.assertIn("publish_package", line)
        self.assertIn("fake-artifactory-local", line)
        self.assertIn("gw-audit-pkg", line)


# ---------------------------------------------------------------------------
# j. BankingPublisherAgent decide_tool
# ---------------------------------------------------------------------------

class TestBankingPublisherAgent(unittest.TestCase):
    """Unit tests for the BankingPublisherAgent class."""

    def setUp(self):
        self.agent = BankingPublisherAgent()

    def test_agent_id_is_banking_publisher(self):
        self.assertEqual(self.agent.agent_id, "banking-publisher")

    def test_decide_tool_returns_publish_package(self):
        decision = self.agent.decide_tool("my-pkg", "hello content")
        self.assertEqual(decision["tool_name"], "publish_package")
        self.assertEqual(decision["arguments"]["package_name"], "my-pkg")
        self.assertEqual(decision["arguments"]["message"], "hello content")

    def test_decide_tool_preserves_message_verbatim(self):
        """The agent must not modify the message — it is inert data."""
        msg = "def get_auth_token():\n    return 'demo-token'"
        decision = self.agent.decide_tool("code-content-pkg", msg)
        self.assertEqual(decision["arguments"]["message"], msg)


# ---------------------------------------------------------------------------
# End-to-end demonstration sequence (test form of demo_phase2_step2.py)
# ---------------------------------------------------------------------------

class TestEndToEndDemoSequence(unittest.TestCase):
    """
    Mirrors the demo_phase2_step2.py sequence as a proper test:

        banking-publisher
            ↓
        publish_package("agent-message", "hello from Agent A")
            ↓
        authorization = ALLOW
            ↓
        Fake Artifactory
            ↓
        package stored
        ↓
        retrieve directly to prove it exists
    """

    def test_full_demo_sequence(self):
        import requests as _requests

        agent = BankingPublisherAgent()
        gateway = PublishGateway(artifactory_url=_fixture.base_url)

        # Step 1: Agent decides tool
        decision = agent.decide_tool("agent-message", "hello from Agent A")
        self.assertEqual(decision["tool_name"], "publish_package")

        # Step 2: Gateway executes with authorization
        context = {"agent_id": agent.agent_id, "user_id": "demo-user"}
        result = gateway.execute_tool(context, decision["tool_name"], decision["arguments"])

        # Step 3: Verify success
        self.assertTrue(result["success"])
        self.assertEqual(result["package"]["name"], "agent-message")
        self.assertEqual(result["package"]["content"], "hello from Agent A")

        # Step 4: Retrieve directly from Fake Artifactory to prove persistence
        resp = _requests.get(
            f"{_fixture.base_url}/packages/agent-message", timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        stored = resp.json()
        self.assertEqual(stored["name"], "agent-message")
        self.assertEqual(stored["content"], "hello from Agent A")
        self.assertIn("published_at", stored)


if __name__ == "__main__":
    unittest.main(verbosity=2)
