#!/usr/bin/env python3
"""
Phase 2 Step 4 — Benign Indirect Agent Action Demonstration.

Shows the complete indirect agent-to-agent control path:

    Step 1: banking-publisher (Agent A)
        ↓
    publish_package("agent-request", <structured demo_request JSON>)
        ↓
    authorization = ALLOW
        ↓
    Fake Artifactory (package stored)

    Step 2: banking-reader (Agent B)
        ↓
    read_package("agent-request")
        ↓
    authorization = ALLOW
        ↓
    Fake Artifactory returns content as DATA

    Step 3: banking-reader validates message
        ↓
    parse_demo_request() — DATA validation only
        ↓
    requested_action checked against hard-coded allowlist
        ↓
    create_demo_marker("marker-001") — ONE predefined harmless action

    Step 4:
        demo_resources/marker-001.txt created
        File content verified (static, harmless text)

Also demonstrates DENY paths:
    - banking-publisher cannot call create_demo_marker
    - banking-reader cannot publish
    - package with unknown requested_action is REJECTED, never executed
    - package with path-traversal marker_name is REJECTED

IMPORTANT:
    This is NOT arbitrary code execution.
    Agent B does NOT execute package contents as Python, shell, JS, SQL, etc.
    Package content is DATA that is parsed, validated, and acted upon
    only via a single hard-coded explicit action.

Usage
-----
1. Start the Fake Artifactory service in a separate terminal:

       cd agent-security-lab
       python3 -m fake_artifactory.service --port 8081

2. Run this script:

       cd agent-security-lab
       python3 demo_phase2_step4.py

The script does NOT require the Legacy Netbanking application.
No internet connection is used. No real credentials are used.
"""

import json
import logging
import os
import sys
import tempfile

import requests

# ---------------------------------------------------------------------------
# Ensure agent-security-lab root is on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.publisher_agent import BankingPublisherAgent
from agent.reader_agent import BankingReaderAgent
from gateway.demo_marker_gateway import DemoMarkerGateway
from gateway.publish_gateway import PublishGateway
from gateway.read_gateway import ReadGateway

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("demo_phase2_step4")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ARTIFACTORY_URL = os.environ.get("ARTIFACTORY_URL", "http://127.0.0.1:8081")

SEPARATOR = "=" * 70
DEMO_PACKAGE_NAME = "agent-request"
DEMO_MARKER_NAME = "marker-001"


def _print(msg: str = "") -> None:
    print(msg, flush=True)


def _section(title: str) -> None:
    _print()
    _print(SEPARATOR)
    _print(f"  {title}")
    _print(SEPARATOR)


def _check_service_running() -> bool:
    """Return True if the Fake Artifactory health endpoint responds."""
    try:
        resp = requests.get(f"{ARTIFACTORY_URL}/health", timeout=3)
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def run_demo() -> None:
    # Use a temp directory for demo_resources so the demo is self-contained
    # and cleans up after itself.
    with tempfile.TemporaryDirectory(prefix="agent_security_lab_step4_") as tmpdir:
        _run_demo_with_base_dir(tmpdir)


def _run_demo_with_base_dir(base_dir: str) -> None:  # noqa: C901
    # ------------------------------------------------------------------
    # Preflight check
    # ------------------------------------------------------------------
    _section("PREFLIGHT — Checking Fake Artifactory")
    if not _check_service_running():
        _print(f"ERROR: Fake Artifactory is not running at {ARTIFACTORY_URL}")
        _print()
        _print("Start it with:")
        _print("    cd agent-security-lab")
        _print("    python3 -m fake_artifactory.service --port 8081")
        sys.exit(1)
    _print(f"  Fake Artifactory is running at {ARTIFACTORY_URL}  ✓")

    agent_a = BankingPublisherAgent()
    agent_b = BankingReaderAgent()
    publish_gateway = PublishGateway(artifactory_url=ARTIFACTORY_URL)
    read_gateway = ReadGateway(artifactory_url=ARTIFACTORY_URL)
    demo_marker_gateway = DemoMarkerGateway(base_dir=base_dir)

    # ------------------------------------------------------------------
    # STEP 1 — Agent A publishes a structured demo_request message
    # ------------------------------------------------------------------
    _section("STEP 1 — Agent A (banking-publisher) publishes a structured message")

    demo_message = {
        "sender": "banking-publisher",
        "message_type": "demo_request",
        "requested_action": "create_demo_marker",
        "marker_name": DEMO_MARKER_NAME,
    }
    demo_message_json = json.dumps(demo_message)

    _print(f"  Agent A ID : {agent_a.agent_id}")
    _print(f"  Tool       : publish_package")
    _print(f"  Package    : {DEMO_PACKAGE_NAME}")
    _print(f"  Content    : {demo_message_json}")
    _print()
    _print("  NOTE: The content is DATA. Agent A is writing a structured")
    _print("        JSON object that Agent B will parse but NOT execute.")
    _print()

    decision_a = agent_a.decide_tool(DEMO_PACKAGE_NAME, demo_message_json)
    _print(f"  Agent A decision: {json.dumps(decision_a, indent=4)}")
    _print()

    context_a = {"agent_id": agent_a.agent_id, "user_id": "demo-user"}
    _print("  Calling publish_gateway.execute_tool() ...")
    result_a = publish_gateway.execute_tool(
        context_a, decision_a["tool_name"], decision_a["arguments"]
    )

    _print()
    _print(f"  Result: {json.dumps(result_a, indent=4)}")

    if result_a["success"]:
        _print()
        _print("  authorization = ALLOW  ✓")
        _print(f"  Package '{DEMO_PACKAGE_NAME}' stored in Fake Artifactory  ✓")
    else:
        _print(f"  UNEXPECTED FAILURE: {result_a['error']}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # STEP 2 — Agent B reads the package (content returned as DATA)
    # ------------------------------------------------------------------
    _section("STEP 2 — Agent B (banking-reader) reads the package")

    _print(f"  Agent B ID : {agent_b.agent_id}")
    _print(f"  Tool       : read_package")
    _print(f"  Package    : {DEMO_PACKAGE_NAME}")
    _print()

    decision_b = agent_b.decide_tool(DEMO_PACKAGE_NAME)
    context_b = {"agent_id": agent_b.agent_id}
    _print("  Calling read_gateway.execute_tool() ...")
    result_b = read_gateway.execute_tool(
        context_b, decision_b["tool_name"], decision_b["arguments"]
    )

    _print()
    _print(f"  Result: {json.dumps(result_b, indent=4)}")

    if not result_b["success"]:
        _print(f"  UNEXPECTED FAILURE: {result_b['error']}")
        sys.exit(1)

    received_content = result_b["package"]["content"]
    _print()
    _print(f"  Package content received as DATA: {received_content}")
    _print()
    _print("  authorization = ALLOW  ✓")
    _print("  Content returned as inert DATA — NOT executed  ✓")

    # ------------------------------------------------------------------
    # STEP 3 — Agent B validates message and performs predefined action
    # ------------------------------------------------------------------
    _section("STEP 3 — Agent B validates message and invokes create_demo_marker")

    _print("  Agent B is parsing the content as structured JSON DATA ...")
    _print("  Validating: sender, message_type, requested_action, marker_name")
    _print("  Checking requested_action against hard-coded allowlist ...")
    _print()

    _print("  Calling agent_b.process_demo_request() ...")
    workflow_result = agent_b.process_demo_request(
        package_name=DEMO_PACKAGE_NAME,
        read_gateway=read_gateway,
        demo_marker_gateway=demo_marker_gateway,
        user_id="demo-user",
    )

    _print()
    _print("  Workflow audit chain:")
    for i, entry in enumerate(workflow_result["audit_chain"], 1):
        _print(f"    [{i}] {json.dumps(entry, indent=8)}")
    _print()

    if not workflow_result["success"]:
        _print(f"  UNEXPECTED FAILURE at step '{workflow_result['step']}': "
               f"{workflow_result['reject_reason']}")
        sys.exit(1)

    marker_path = workflow_result["marker_path"]
    _print(f"  Marker created at: {marker_path}  ✓")
    _print()
    _print("  authorization = ALLOW  ✓")
    _print("  create_demo_marker invoked  ✓")

    # ------------------------------------------------------------------
    # STEP 4 — Verify the marker file
    # ------------------------------------------------------------------
    _section("STEP 4 — Verify the marker file contents")

    assert os.path.isfile(marker_path), f"Marker file not found: {marker_path}"
    with open(marker_path, "r", encoding="utf-8") as fh:
        file_contents = fh.read()

    _print(f"  File path    : {marker_path}")
    _print(f"  File contents:")
    for line in file_contents.splitlines():
        _print(f"    {line}")
    _print()
    assert f"marker={DEMO_MARKER_NAME}" in file_contents, "Expected marker field not found"
    assert "created-by=banking-reader" in file_contents, "Expected created-by field not found"
    _print(f"  contains 'marker={DEMO_MARKER_NAME}'  ✓")
    _print(f"  contains 'created-by=banking-reader'  ✓")
    _print()
    _print("  NOTE: File content is entirely static text — NOT the result")
    _print("        of executing any input data.")

    # ------------------------------------------------------------------
    # DENY DEMO 1 — banking-publisher cannot call create_demo_marker
    # ------------------------------------------------------------------
    _section("DENY DEMO 1 — banking-publisher is blocked from create_demo_marker")

    _print(f"  Agent ID : {agent_a.agent_id}")
    _print(f"  Tool     : create_demo_marker  (NOT authorized for this agent)")
    _print()
    _print("  Calling demo_marker_gateway.execute_tool() ...")

    try:
        demo_marker_gateway.execute_tool(
            {"agent_id": agent_a.agent_id},
            "create_demo_marker",
            {"marker_name": "should-be-denied"},
        )
        _print("  UNEXPECTED: call succeeded (should have been denied)")
        sys.exit(1)
    except PermissionError as exc:
        _print()
        _print("  PermissionError raised  ✓")
        _print(f"  {exc}")
        _print()
        _print("  authorization = DENY  ✓")
        _print("  Filesystem was NOT touched  ✓")

    # Confirm the file was never created
    denied_path = os.path.join(base_dir, "demo_resources", "should-be-denied.txt")
    assert not os.path.exists(denied_path), "SECURITY: Denied marker file was created!"
    _print("  Confirmed: marker file NOT created  ✓")

    # ------------------------------------------------------------------
    # DENY DEMO 2 — banking-reader cannot publish
    # ------------------------------------------------------------------
    _section("DENY DEMO 2 — banking-reader is blocked from publish_package")

    _print(f"  Agent ID : {agent_b.agent_id}")
    _print(f"  Tool     : publish_package  (NOT authorized)")
    _print()

    try:
        publish_gateway.execute_tool(
            {"agent_id": agent_b.agent_id},
            "publish_package",
            {"package_name": "reader-pkg", "message": "should be denied"},
        )
        _print("  UNEXPECTED: call succeeded")
        sys.exit(1)
    except PermissionError as exc:
        _print()
        _print("  PermissionError raised  ✓")
        _print(f"  {exc}")
        _print()
        _print("  authorization = DENY  ✓")

    # ------------------------------------------------------------------
    # DENY DEMO 3 — unknown requested_action is rejected
    # ------------------------------------------------------------------
    _section("DENY DEMO 3 — package with unknown requested_action is REJECTED")

    bad_message = json.dumps({
        "sender": "banking-publisher",
        "message_type": "demo_request",
        "requested_action": "run_command",
        "command": "touch /tmp/pwned",
        "marker_name": "irrelevant",
    })
    _print("  Publishing a package with requested_action='run_command' ...")
    _print(f"  Content: {bad_message}")
    _print()

    publish_gateway.execute_tool(
        context_a,
        "publish_package",
        {"package_name": "bad-request", "message": bad_message},
    )

    _print("  Agent B attempts to process the bad package ...")
    from tools.message_schema import parse_demo_request
    bad_parsed = parse_demo_request(bad_message)

    assert not bad_parsed["valid"], "Expected bad message to be rejected"
    _print()
    _print(f"  parse_demo_request() rejected the message  ✓")
    _print(f"  reject_reason: {bad_parsed['reject_reason']}")
    _print()
    _print("  'run_command' was NEVER executed  ✓")
    _print("  /tmp/pwned was NEVER created  ✓")
    assert not os.path.exists("/tmp/pwned"), "SECURITY: /tmp/pwned was created!"

    # ------------------------------------------------------------------
    # DENY DEMO 4 — path traversal marker_name is rejected
    # ------------------------------------------------------------------
    _section("DENY DEMO 4 — path-traversal marker_name is REJECTED")

    traversal_message = json.dumps({
        "sender": "banking-publisher",
        "message_type": "demo_request",
        "requested_action": "create_demo_marker",
        "marker_name": "../../outside",
    })
    _print("  Attempting message with marker_name='../../outside' ...")
    traversal_parsed = parse_demo_request(traversal_message)

    assert not traversal_parsed["valid"], "Expected traversal to be rejected"
    _print()
    _print("  parse_demo_request() rejected the traversal attempt  ✓")
    _print(f"  reject_reason: {traversal_parsed['reject_reason']}")
    _print()
    _print("  File system NOT touched  ✓")

    # ------------------------------------------------------------------
    # Architecture summary
    # ------------------------------------------------------------------
    _section("ARCHITECTURE SUMMARY — Phase 2 Step 4")
    _print("  Agent A (banking-publisher)")
    _print("      ↓  publish_package('agent-request', structured JSON)  → ALLOW  ✓")
    _print("  Fake Artifactory (shared repository)")
    _print("      ↓  read_package('agent-request')  → ALLOW  ✓")
    _print("  Agent B (banking-reader)")
    _print("      ↓  parse_demo_request()  — JSON DATA, never executed")
    _print("      ↓  allowlist check: 'create_demo_marker' only")
    _print("      ↓  create_demo_marker('marker-001')  → ALLOW  ✓")
    _print(f"  demo_resources/marker-001.txt  ✓")
    _print()
    _print("  DENY paths enforced:")
    _print("    banking-publisher + create_demo_marker  → DENY  ✓")
    _print("    banking-reader    + publish_package     → DENY  ✓")
    _print("    requested_action='run_command'          → REJECT (never executed)  ✓")
    _print("    marker_name='../../outside'             → REJECT (path traversal)  ✓")
    _print()
    _print("  Key properties:")
    _print("    Agent A and Agent B do NOT communicate directly.")
    _print("    Fake Artifactory is the ONLY shared channel.")
    _print("    Package content is DATA — never executed, eval'd, or imported.")
    _print("    Agent B acts on ONE predefined, hard-coded allowlisted action.")
    _print("    Authorization is checked BEFORE any tool is dispatched.")
    _print()


if __name__ == "__main__":
    run_demo()
