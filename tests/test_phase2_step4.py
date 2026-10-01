"""
Phase 2 Step 4 — Comprehensive Test Suite.

Tests cover all required cases A–J plus additional positive tests.

Cases
-----
A. Agent B can perform create_demo_marker directly when authorized.
B. Agent A cannot call create_demo_marker.
C. Agent B cannot publish.
D. A package requesting an unknown action is rejected.
E. A package containing {"requested_action": "run_command", "command": ...}
   is rejected and NEVER executed.
F. A package containing marker_name="../../outside" is rejected.
G. Agent B cannot write outside demo_resources/.
H. Denied actions are logged.
I. Allowed action is logged.
J. Full end-to-end flow works: A → publish → Artifactory → B reads →
   B performs predefined action → marker created.

All tests are self-contained (no network required for most; live Artifactory
used only in the full end-to-end tests which are skipped when not running).
"""

import json
import logging
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

# Ensure agent-security-lab root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.publisher_agent import BankingPublisherAgent
from agent.reader_agent import BankingReaderAgent
from fake_artifactory.service import create_server
from gateway.authorization_policy import check_authorization, LOCAL_DEMO_RESOURCE, REPOSITORY_NAME
from gateway.demo_marker_gateway import DemoMarkerGateway
from gateway.publish_gateway import PublishGateway
from gateway.read_gateway import ReadGateway
from tools.demo_marker_tool import create_demo_marker, _is_valid_marker_name
from tools.message_schema import parse_demo_request

# ---------------------------------------------------------------------------
# Shared in-process Fake Artifactory fixture
# ---------------------------------------------------------------------------
_FIXTURE_PORT = 8895  # Distinct port — avoids clashes with other test modules


class _ArtifactoryFixture:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server = create_server(
            host="127.0.0.1",
            port=_FIXTURE_PORT,
            storage_dir=self.temp_dir,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{_FIXTURE_PORT}"

    def teardown(self):
        self.server.shutdown()


_fixture: _ArtifactoryFixture | None = None


def setUpModule():
    global _fixture
    _fixture = _ArtifactoryFixture()


def tearDownModule():
    if _fixture:
        _fixture.teardown()


def _direct_publish(base_url: str, package_name: str, content: str) -> None:
    """Helper: publish a package directly via HTTP (bypasses auth gateway)."""
    import requests

    resp = requests.post(
        f"{base_url}/packages/{package_name}",
        json={"content": content},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    assert resp.status_code == 201, f"Direct publish failed: {resp.text}"


# ===========================================================================
# A. Agent B can perform create_demo_marker directly when authorized
# ===========================================================================
class TestCaseA_AgentBCanCreateMarker(unittest.TestCase):
    """Case A: Agent B can perform create_demo_marker when authorized."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_authorized_agent_b_creates_marker(self):
        result = self.gateway.execute_tool(
            {"agent_id": "banking-reader"},
            "create_demo_marker",
            {"marker_name": "marker-001"},
        )
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["marker_path"])
        self.assertTrue(os.path.isfile(result["marker_path"]))

    def test_marker_file_contains_expected_text(self):
        result = self.gateway.execute_tool(
            {"agent_id": "banking-reader"},
            "create_demo_marker",
            {"marker_name": "marker-abc"},
        )
        with open(result["marker_path"], "r") as fh:
            contents = fh.read()
        self.assertIn("marker=marker-abc", contents)
        self.assertIn("created-by=banking-reader", contents)

    def test_marker_file_is_inside_demo_resources(self):
        result = self.gateway.execute_tool(
            {"agent_id": "banking-reader"},
            "create_demo_marker",
            {"marker_name": "marker-xyz"},
        )
        demo_dir = os.path.join(self.tmpdir, "demo_resources")
        self.assertTrue(result["marker_path"].startswith(demo_dir))

    def test_policy_allows_banking_reader_create_demo_marker(self):
        authz = check_authorization(
            agent_id="banking-reader",
            tool_name="create_demo_marker",
            target_repository=LOCAL_DEMO_RESOURCE,
        )
        self.assertEqual(authz["decision"], "ALLOW")


# ===========================================================================
# B. Agent A cannot call create_demo_marker
# ===========================================================================
class TestCaseB_AgentACannotCreateMarker(unittest.TestCase):
    """Case B: Agent A (banking-publisher) cannot call create_demo_marker."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_agent_a_create_marker_raises_permission_error(self):
        with self.assertRaises(PermissionError) as cm:
            self.gateway.execute_tool(
                {"agent_id": "banking-publisher"},
                "create_demo_marker",
                {"marker_name": "should-be-denied"},
            )
        self.assertIn("banking-publisher", str(cm.exception))

    def test_agent_a_marker_file_never_created(self):
        """Filesystem is NOT touched when authorization is denied."""
        try:
            self.gateway.execute_tool(
                {"agent_id": "banking-publisher"},
                "create_demo_marker",
                {"marker_name": "should-be-denied"},
            )
        except PermissionError:
            pass
        denied_path = os.path.join(self.tmpdir, "demo_resources", "should-be-denied.txt")
        self.assertFalse(os.path.exists(denied_path))

    def test_policy_denies_banking_publisher_create_demo_marker(self):
        authz = check_authorization(
            agent_id="banking-publisher",
            tool_name="create_demo_marker",
            target_repository=LOCAL_DEMO_RESOURCE,
        )
        self.assertEqual(authz["decision"], "DENY")


# ===========================================================================
# C. Agent B cannot publish
# ===========================================================================
class TestCaseC_AgentBCannotPublish(unittest.TestCase):
    """Case C: Agent B (banking-reader) cannot publish."""

    def setUp(self):
        self.gateway = PublishGateway(artifactory_url=_fixture.base_url)

    def test_agent_b_publish_raises_permission_error(self):
        with self.assertRaises(PermissionError) as cm:
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "publish_package",
                {"package_name": "reader-pkg", "message": "should be denied"},
            )
        self.assertIn("banking-reader", str(cm.exception))

    def test_agent_b_publish_never_reaches_artifactory(self):
        """Artifactory is NOT called when authorization is denied."""
        import requests

        try:
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "publish_package",
                {"package_name": "forbidden-pkg", "message": "data"},
            )
        except PermissionError:
            pass

        resp = requests.get(
            f"{_fixture.base_url}/packages/forbidden-pkg", timeout=5
        )
        self.assertEqual(resp.status_code, 404)

    def test_policy_denies_banking_reader_publish(self):
        authz = check_authorization(
            agent_id="banking-reader",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(authz["decision"], "DENY")


# ===========================================================================
# D. A package requesting an unknown action is rejected
# ===========================================================================
class TestCaseD_UnknownActionRejected(unittest.TestCase):
    """Case D: Unknown requested_action is rejected before any dispatch."""

    def test_unknown_action_rejected_by_schema(self):
        msg = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "delete_database",
            "marker_name": "irrelevant",
        })
        result = parse_demo_request(msg)
        self.assertFalse(result["valid"])
        self.assertIn("delete_database", result["reject_reason"])
        self.assertIn("allowlist", result["reject_reason"])

    def test_unknown_action_never_dispatched(self):
        """Confirm the tool layer is never reached for an unknown action."""
        tmpdir = tempfile.mkdtemp()
        gateway = DemoMarkerGateway(base_dir=tmpdir)
        agent_b = BankingReaderAgent()

        # Inject pre-crafted read result to avoid Artifactory dependency
        bad_content = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "delete_database",
            "marker_name": "irrelevant",
        })
        mock_read_gw = MagicMock()
        mock_read_gw.execute_tool.return_value = {
            "success": True,
            "package": {"name": "pkg", "content": bad_content, "published_at": "now"},
            "error": None,
        }

        result = agent_b.process_demo_request(
            package_name="pkg",
            read_gateway=mock_read_gw,
            demo_marker_gateway=gateway,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["step"], "message_validation")
        # Gateway tool was never called
        gateway_mock_result_dir = os.path.join(tmpdir, "demo_resources")
        self.assertFalse(os.path.exists(gateway_mock_result_dir))


# ===========================================================================
# E. run_command package is rejected and NEVER executed
# ===========================================================================
class TestCaseE_RunCommandNeverExecuted(unittest.TestCase):
    """
    Case E: Package with requested_action='run_command' is rejected
    and the command is NEVER executed.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.marker_gateway = DemoMarkerGateway(base_dir=self.tmpdir)
        self.agent_b = BankingReaderAgent()

    def test_run_command_schema_rejected(self):
        msg = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "run_command",
            "command": "touch /tmp/pwned_E",
            "marker_name": "irrelevant",
        })
        result = parse_demo_request(msg)
        self.assertFalse(result["valid"])
        self.assertIn("run_command", result["reject_reason"])

    def test_run_command_file_never_created(self):
        """Verify /tmp/pwned_E is NOT created."""
        sentinel = "/tmp/pwned_E"
        if os.path.exists(sentinel):
            os.remove(sentinel)

        msg = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "run_command",
            "command": f"touch {sentinel}",
            "marker_name": "irrelevant",
        })
        mock_gw = MagicMock()
        mock_gw.execute_tool.return_value = {
            "success": True,
            "package": {"name": "pkg", "content": msg, "published_at": "now"},
            "error": None,
        }
        result = self.agent_b.process_demo_request(
            package_name="pkg",
            read_gateway=mock_gw,
            demo_marker_gateway=self.marker_gateway,
        )
        self.assertFalse(result["success"])
        self.assertFalse(os.path.exists(sentinel))

    def test_run_command_workflow_rejects_at_validation_step(self):
        msg = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "run_command",
            "command": "rm -rf /",
            "marker_name": "irrelevant",
        })
        mock_gw = MagicMock()
        mock_gw.execute_tool.return_value = {
            "success": True,
            "package": {"name": "pkg", "content": msg, "published_at": "now"},
            "error": None,
        }
        result = self.agent_b.process_demo_request(
            package_name="pkg",
            read_gateway=mock_gw,
            demo_marker_gateway=self.marker_gateway,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["step"], "message_validation")


# ===========================================================================
# F. Path-traversal marker_name is rejected
# ===========================================================================
class TestCaseF_PathTraversalRejected(unittest.TestCase):
    """Case F: marker_name with path traversal is rejected."""

    TRAVERSAL_CASES = [
        "../../outside",
        "../sibling",
        "/etc/passwd",
        "..\\windows\\system32",
        "foo/bar",
        "foo\\bar",
    ]

    def test_schema_rejects_traversal_marker_names(self):
        for bad_name in self.TRAVERSAL_CASES:
            with self.subTest(marker_name=bad_name):
                msg = json.dumps({
                    "sender": "banking-publisher",
                    "message_type": "demo_request",
                    "requested_action": "create_demo_marker",
                    "marker_name": bad_name,
                })
                result = parse_demo_request(msg)
                self.assertFalse(result["valid"], f"Expected rejection for '{bad_name}'")

    def test_tool_rejects_traversal_marker_names(self):
        tmpdir = tempfile.mkdtemp()
        for bad_name in self.TRAVERSAL_CASES:
            with self.subTest(marker_name=bad_name):
                with self.assertRaises(ValueError, msg=f"Expected ValueError for '{bad_name}'"):
                    create_demo_marker(
                        agent_id="banking-reader",
                        marker_name=bad_name,
                        base_dir=tmpdir,
                    )

    def test_validator_rejects_traversal_directly(self):
        for bad_name in self.TRAVERSAL_CASES:
            with self.subTest(marker_name=bad_name):
                self.assertFalse(_is_valid_marker_name(bad_name))


# ===========================================================================
# G. Agent B cannot write outside demo_resources/
# ===========================================================================
class TestCaseG_NoWriteOutsideDemoResources(unittest.TestCase):
    """Case G: Writes are constrained to demo_resources/ only."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_valid_marker_stays_inside_demo_resources(self):
        result = create_demo_marker(
            agent_id="banking-reader",
            marker_name="safe-marker",
            base_dir=self.tmpdir,
        )
        self.assertTrue(result["success"])
        demo_dir = os.path.abspath(os.path.join(self.tmpdir, "demo_resources"))
        self.assertTrue(result["marker_path"].startswith(demo_dir + os.sep))

    def test_empty_marker_name_raises_value_error(self):
        with self.assertRaises(ValueError):
            create_demo_marker(
                agent_id="banking-reader",
                marker_name="",
                base_dir=self.tmpdir,
            )

    def test_marker_name_with_special_chars_raises(self):
        for bad in ("marker;cmd", "marker|pipe", "marker$(subshell)", "marker`backtick`"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    create_demo_marker(
                        agent_id="banking-reader",
                        marker_name=bad,
                        base_dir=self.tmpdir,
                    )


# ===========================================================================
# H. Denied actions are logged
# ===========================================================================
class TestCaseH_DeniedActionsAreLogged(unittest.TestCase):
    """Case H: Denied actions emit log records."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_deny_emits_authz_warning(self):
        with self.assertLogs("agent-security-lab.gateway", level="WARNING") as captured:
            try:
                self.gateway.execute_tool(
                    {"agent_id": "banking-publisher"},
                    "create_demo_marker",
                    {"marker_name": "should-fail"},
                )
            except PermissionError:
                pass

        deny_found = any("AUTHZ DENIED" in line for line in captured.output)
        self.assertTrue(deny_found, "Expected AUTHZ DENIED log record")

    def test_deny_log_contains_agent_id(self):
        with self.assertLogs("agent-security-lab.gateway", level="WARNING") as captured:
            try:
                self.gateway.execute_tool(
                    {"agent_id": "banking-publisher"},
                    "create_demo_marker",
                    {"marker_name": "should-fail"},
                )
            except PermissionError:
                pass

        combined = "\n".join(captured.output)
        self.assertIn("banking-publisher", combined)

    def test_schema_rejection_emits_warning(self):
        with self.assertLogs("agent-security-lab.message_schema", level="WARNING") as captured:
            result = parse_demo_request(json.dumps({
                "sender": "banking-publisher",
                "message_type": "demo_request",
                "requested_action": "evil_action",
                "marker_name": "irrelevant",
            }))
        self.assertFalse(result["valid"])
        self.assertTrue(any("REJECT" in line for line in captured.output))


# ===========================================================================
# I. Allowed action is logged
# ===========================================================================
class TestCaseI_AllowedActionIsLogged(unittest.TestCase):
    """Case I: Allowed actions emit audit log records."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_allow_emits_audit_log_tool_layer(self):
        with self.assertLogs("agent-security-lab.tools", level="INFO") as captured:
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "create_demo_marker",
                {"marker_name": "logged-marker"},
            )
        combined = "\n".join(captured.output)
        self.assertIn("[AUDIT]", combined)
        self.assertIn("create_demo_marker", combined)
        self.assertIn("ALLOWED", combined)
        self.assertIn("SUCCESS", combined)

    def test_allow_emits_audit_log_gateway_layer(self):
        with self.assertLogs("agent-security-lab.gateway", level="INFO") as captured:
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "create_demo_marker",
                {"marker_name": "logged-marker-2"},
            )
        combined = "\n".join(captured.output)
        self.assertIn("banking-reader", combined)
        self.assertIn("create_demo_marker", combined)

    def test_allowed_audit_contains_marker_name(self):
        with self.assertLogs("agent-security-lab.tools", level="INFO") as captured:
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "create_demo_marker",
                {"marker_name": "specific-marker"},
            )
        combined = "\n".join(captured.output)
        self.assertIn("specific-marker", combined)


# ===========================================================================
# J. Full end-to-end flow
# ===========================================================================
class TestCaseJ_EndToEndFlow(unittest.TestCase):
    """
    Case J: Full end-to-end flow:
        Agent A → publish → Fake Artifactory → Agent B reads →
        Agent B performs predefined action → marker created.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.agent_a = BankingPublisherAgent()
        self.agent_b = BankingReaderAgent()
        self.publish_gateway = PublishGateway(artifactory_url=_fixture.base_url)
        self.read_gateway = ReadGateway(artifactory_url=_fixture.base_url)
        self.demo_marker_gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_full_chain_produces_marker_file(self):
        # Step 1: Agent A publishes a structured message
        demo_message = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
            "marker_name": "e2e-marker",
        })
        decision_a = self.agent_a.decide_tool("e2e-pkg", demo_message)
        result_a = self.publish_gateway.execute_tool(
            {"agent_id": "banking-publisher"},
            decision_a["tool_name"],
            decision_a["arguments"],
        )
        self.assertTrue(result_a["success"])

        # Step 2–4: Agent B reads, validates, creates marker
        result_b = self.agent_b.process_demo_request(
            package_name="e2e-pkg",
            read_gateway=self.read_gateway,
            demo_marker_gateway=self.demo_marker_gateway,
        )
        self.assertTrue(result_b["success"], f"Workflow failed: {result_b}")
        self.assertIsNotNone(result_b["marker_path"])
        self.assertTrue(os.path.isfile(result_b["marker_path"]))

        # Verify the file contains expected harmless text
        with open(result_b["marker_path"], "r") as fh:
            contents = fh.read()
        self.assertIn("marker=e2e-marker", contents)
        self.assertIn("created-by=banking-reader", contents)

    def test_audit_chain_contains_all_steps(self):
        """Audit chain must record read + validation + create_marker."""
        demo_message = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
            "marker_name": "audit-chain-marker",
        })
        _direct_publish(_fixture.base_url, "audit-chain-pkg", demo_message)

        result = self.agent_b.process_demo_request(
            package_name="audit-chain-pkg",
            read_gateway=self.read_gateway,
            demo_marker_gateway=self.demo_marker_gateway,
        )
        self.assertTrue(result["success"])

        tools_in_chain = [entry["tool"] for entry in result["audit_chain"]]
        self.assertIn("read_package", tools_in_chain)
        self.assertIn("create_demo_marker", tools_in_chain)

    def test_agents_do_not_call_each_other_directly(self):
        """Agent A and Agent B have no direct method calls between them."""
        # Verify the agents have no reference to each other
        self.assertFalse(hasattr(self.agent_a, "agent_b"))
        self.assertFalse(hasattr(self.agent_b, "agent_a"))
        # No direct method-call channel exists between the agents
        self.assertFalse(hasattr(self.agent_a, "read_package"))
        self.assertFalse(hasattr(self.agent_b, "publish"))

    def test_content_never_executed(self):
        """
        Package content containing Python-like code is returned as DATA
        and never executed by the workflow.
        """
        # Publish a malformed message that would cause harm if exec'd
        # (but only a valid demo_request if create_demo_marker is requested)
        demo_message = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "exec(__import__('os').system('touch /tmp/not_executed'))",
            "marker_name": "harmless",
        })
        _direct_publish(_fixture.base_url, "exec-test-pkg", demo_message)

        result = self.agent_b.process_demo_request(
            package_name="exec-test-pkg",
            read_gateway=self.read_gateway,
            demo_marker_gateway=self.demo_marker_gateway,
        )
        # Workflow must reject — the requested_action is not in the allowlist
        self.assertFalse(result["success"])
        self.assertFalse(os.path.exists("/tmp/not_executed"))

    def test_marker_constrained_to_demo_resources(self):
        """Marker file path is inside demo_resources/."""
        demo_message = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
            "marker_name": "path-check",
        })
        _direct_publish(_fixture.base_url, "path-check-pkg", demo_message)

        result = self.agent_b.process_demo_request(
            package_name="path-check-pkg",
            read_gateway=self.read_gateway,
            demo_marker_gateway=self.demo_marker_gateway,
        )
        self.assertTrue(result["success"])
        demo_dir = os.path.join(self.tmpdir, "demo_resources")
        self.assertTrue(result["marker_path"].startswith(demo_dir))


# ===========================================================================
# Additional: Policy table completeness for Step 4 entries
# ===========================================================================
class TestStep4PolicyTableCompleteness(unittest.TestCase):
    """Verify authorization policy contains the expected Step 4 entries."""

    def test_banking_reader_create_demo_marker_allowed(self):
        authz = check_authorization(
            agent_id="banking-reader",
            tool_name="create_demo_marker",
            target_repository=LOCAL_DEMO_RESOURCE,
        )
        self.assertEqual(authz["decision"], "ALLOW")

    def test_banking_publisher_create_demo_marker_denied(self):
        authz = check_authorization(
            agent_id="banking-publisher",
            tool_name="create_demo_marker",
            target_repository=LOCAL_DEMO_RESOURCE,
        )
        self.assertEqual(authz["decision"], "DENY")

    def test_banking_reader_create_marker_wrong_repo_denied(self):
        authz = check_authorization(
            agent_id="banking-reader",
            tool_name="create_demo_marker",
            target_repository="fake-artifactory-local",
        )
        self.assertEqual(authz["decision"], "DENY")

    def test_unknown_agent_create_marker_denied(self):
        authz = check_authorization(
            agent_id="unknown-agent",
            tool_name="create_demo_marker",
            target_repository=LOCAL_DEMO_RESOURCE,
        )
        self.assertEqual(authz["decision"], "DENY")

    # Confirm existing Step 3 policy entries still intact
    def test_banking_publisher_publish_still_allowed(self):
        authz = check_authorization(
            agent_id="banking-publisher",
            tool_name="publish_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(authz["decision"], "ALLOW")

    def test_banking_reader_read_still_allowed(self):
        authz = check_authorization(
            agent_id="banking-reader",
            tool_name="read_package",
            target_repository=REPOSITORY_NAME,
        )
        self.assertEqual(authz["decision"], "ALLOW")


# ===========================================================================
# Additional: Message schema validation
# ===========================================================================
class TestMessageSchemaValidation(unittest.TestCase):
    """Thorough validation of parse_demo_request() behaviour."""

    def _valid_msg(self, **overrides) -> str:
        base = {
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
            "marker_name": "marker-001",
        }
        base.update(overrides)
        return json.dumps(base)

    def test_valid_message_accepted(self):
        result = parse_demo_request(self._valid_msg())
        self.assertTrue(result["valid"])
        self.assertEqual(result["requested_action"], "create_demo_marker")
        self.assertEqual(result["marker_name"], "marker-001")

    def test_missing_sender_rejected(self):
        msg = json.dumps({
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
            "marker_name": "marker-001",
        })
        result = parse_demo_request(msg)
        self.assertFalse(result["valid"])

    def test_missing_marker_name_rejected(self):
        msg = json.dumps({
            "sender": "banking-publisher",
            "message_type": "demo_request",
            "requested_action": "create_demo_marker",
        })
        result = parse_demo_request(msg)
        self.assertFalse(result["valid"])

    def test_wrong_sender_rejected(self):
        result = parse_demo_request(self._valid_msg(sender="evil-agent"))
        self.assertFalse(result["valid"])

    def test_wrong_message_type_rejected(self):
        result = parse_demo_request(self._valid_msg(message_type="exploit_payload"))
        self.assertFalse(result["valid"])

    def test_not_json_rejected(self):
        result = parse_demo_request("this is not json")
        self.assertFalse(result["valid"])

    def test_empty_string_rejected(self):
        result = parse_demo_request("")
        self.assertFalse(result["valid"])

    def test_json_array_rejected(self):
        result = parse_demo_request("[1, 2, 3]")
        self.assertFalse(result["valid"])

    def test_sql_injection_in_marker_name_rejected(self):
        result = parse_demo_request(self._valid_msg(marker_name="'; DROP TABLE markers; --"))
        self.assertFalse(result["valid"])

    def test_exec_in_requested_action_rejected(self):
        result = parse_demo_request(self._valid_msg(requested_action="exec('import os')"))
        self.assertFalse(result["valid"])

    def test_valid_marker_names_accepted(self):
        for name in ("marker-001", "abc", "test_123", "A-B-C", "x" * 64):
            with self.subTest(name=name):
                result = parse_demo_request(self._valid_msg(marker_name=name))
                self.assertTrue(result["valid"], f"Expected valid for '{name}'")

    def test_too_long_marker_name_rejected(self):
        result = parse_demo_request(self._valid_msg(marker_name="a" * 65))
        self.assertFalse(result["valid"])


# ===========================================================================
# Additional: DemoMarkerGateway edge cases
# ===========================================================================
class TestDemoMarkerGatewayEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = DemoMarkerGateway(base_dir=self.tmpdir)

    def test_missing_agent_id_raises_value_error(self):
        with self.assertRaises(ValueError) as cm:
            self.gateway.execute_tool(
                {},
                "create_demo_marker",
                {"marker_name": "test"},
            )
        self.assertIn("agent_id", str(cm.exception))

    def test_unknown_tool_raises_after_authz(self):
        # banking-reader has no auth for "unknown_tool" on local-demo-resource
        with self.assertRaises(PermissionError):
            self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "unknown_tool",
                {},
            )

    def test_multiple_markers_can_be_created(self):
        for i in range(3):
            result = self.gateway.execute_tool(
                {"agent_id": "banking-reader"},
                "create_demo_marker",
                {"marker_name": f"multi-{i}"},
            )
            self.assertTrue(result["success"])
            self.assertTrue(os.path.isfile(result["marker_path"]))


if __name__ == "__main__":
    unittest.main()
