#!/usr/bin/env python3
"""
Phase 2 Step 3 — Agent A → Repository → Agent B Demonstration.

Shows the complete publish-then-read flow:

    Step 1: banking-publisher (Agent A)
        ↓
    publish_package("agent-message", "hello from Agent A")
        ↓
    authorization = ALLOW
        ↓
    Fake Artifactory (package stored)

    Step 2: banking-reader (Agent B)
        ↓
    read_package("agent-message")
        ↓
    authorization = ALLOW
        ↓
    Fake Artifactory (package retrieved)

    Step 3: banking-reader receives "hello from Agent A"

Also demonstrates the DENY paths:

    banking-reader  → publish_package  → DENY (not a publisher)
    banking-publisher → read_package  → DENY (not a reader)

Usage
-----
1. Start the Fake Artifactory service in a separate terminal:

       cd agent-security-lab
       python3 -m fake_artifactory.service --port 8081

2. Run this script:

       cd agent-security-lab
       python3 demo_phase2_step3.py

The script does NOT require the Legacy Netbanking application.
No internet connection is used. No real credentials are used.
"""

import json
import logging
import os
import sys

import requests

# ---------------------------------------------------------------------------
# Ensure agent-security-lab root is on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.publisher_agent import BankingPublisherAgent
from agent.reader_agent import BankingReaderAgent
from gateway.publish_gateway import PublishGateway
from gateway.read_gateway import ReadGateway

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("demo_phase2_step3")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ARTIFACTORY_URL = os.environ.get("ARTIFACTORY_URL", "http://127.0.0.1:8081")

SEPARATOR = "=" * 70


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

    # ------------------------------------------------------------------
    # STEP 1 — Agent A publishes a package
    # ------------------------------------------------------------------
    _section("STEP 1 — Agent A (banking-publisher) publishes a package")

    _print(f"  Agent A ID : {agent_a.agent_id}")
    _print(f"  Tool       : publish_package")
    _print(f"  Package    : agent-message")
    _print(f"  Content    : hello from Agent A")
    _print()

    decision_a = agent_a.decide_tool("agent-message", "hello from Agent A")
    _print(f"  Agent A decision: {json.dumps(decision_a, indent=4)}")
    _print()

    context_a = {"agent_id": agent_a.agent_id, "user_id": "demo-user"}
    _print("  Calling publish_gateway.execute_tool() ...")
    result_a = publish_gateway.execute_tool(context_a, decision_a["tool_name"], decision_a["arguments"])

    _print()
    _print(f"  Result: {json.dumps(result_a, indent=4)}")

    if result_a["success"]:
        _print()
        _print("  authorization = ALLOW  ✓")
        _print("  Package stored in Fake Artifactory  ✓")
    else:
        _print(f"  UNEXPECTED FAILURE: {result_a['error']}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # STEP 2 — Agent B reads the package Agent A published
    # ------------------------------------------------------------------
    _section("STEP 2 — Agent B (banking-reader) reads the package")

    _print(f"  Agent B ID : {agent_b.agent_id}")
    _print(f"  Tool       : read_package")
    _print(f"  Package    : agent-message")
    _print()

    decision_b = agent_b.decide_tool("agent-message")
    _print(f"  Agent B decision: {json.dumps(decision_b, indent=4)}")
    _print()

    context_b = {"agent_id": agent_b.agent_id}
    _print("  Calling read_gateway.execute_tool() ...")
    result_b = read_gateway.execute_tool(context_b, decision_b["tool_name"], decision_b["arguments"])

    _print()
    _print(f"  Result: {json.dumps(result_b, indent=4)}")

    if not result_b["success"]:
        _print(f"  UNEXPECTED FAILURE: {result_b['error']}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # STEP 3 — Verify Agent B received Agent A's content
    # ------------------------------------------------------------------
    _section("STEP 3 — Content received by Agent B")

    received_content = result_b["package"]["content"]
    _print(f"  Package name    : {result_b['package']['name']}")
    _print(f"  Package content : {received_content}")
    _print(f"  Published at    : {result_b['package']['published_at']}")
    _print()

    expected = "hello from Agent A"
    if received_content == expected:
        _print(f"  Content matches expected '{expected}'  ✓")
        _print()
        _print("  NOTE: Content was returned as inert data — NOT executed.")
    else:
        _print(f"  UNEXPECTED CONTENT: got '{received_content}', expected '{expected}'")
        sys.exit(1)

    # ------------------------------------------------------------------
    # DENY DEMO 1 — banking-reader cannot publish
    # ------------------------------------------------------------------
    _section("DENY DEMO 1 — banking-reader is blocked from publish_package")

    _print(f"  Agent ID : {agent_b.agent_id}")
    _print(f"  Tool     : publish_package  (NOT authorized)")
    _print()
    _print("  Calling publish_gateway.execute_tool() ...")

    try:
        publish_gateway.execute_tool(
            {"agent_id": agent_b.agent_id},
            "publish_package",
            {"package_name": "reader-pkg", "message": "should be denied"},
        )
        _print("  UNEXPECTED: call succeeded (should have been denied)")
        sys.exit(1)
    except PermissionError as exc:
        _print()
        _print(f"  PermissionError raised  ✓")
        _print(f"  {exc}")
        _print()
        _print("  authorization = DENY  ✓")
        _print("  Fake Artifactory was NOT called  ✓")

    # Confirm package was never stored
    resp = requests.get(f"{ARTIFACTORY_URL}/packages/reader-pkg", timeout=5)
    assert resp.status_code == 404, f"Expected 404 but got {resp.status_code}"
    _print("  Confirmed: reader-pkg NOT present in Artifactory (HTTP 404)  ✓")

    # ------------------------------------------------------------------
    # DENY DEMO 2 — banking-publisher cannot read
    # ------------------------------------------------------------------
    _section("DENY DEMO 2 — banking-publisher is blocked from read_package")

    _print(f"  Agent ID : {agent_a.agent_id}")
    _print(f"  Tool     : read_package  (NOT authorized)")
    _print()
    _print("  Calling read_gateway.execute_tool() ...")

    try:
        read_gateway.execute_tool(
            {"agent_id": agent_a.agent_id},
            "read_package",
            {"package_name": "agent-message"},
        )
        _print("  UNEXPECTED: call succeeded (should have been denied)")
        sys.exit(1)
    except PermissionError as exc:
        _print()
        _print(f"  PermissionError raised  ✓")
        _print(f"  {exc}")
        _print()
        _print("  authorization = DENY  ✓")
        _print("  Fake Artifactory was NOT called  ✓")

    # ------------------------------------------------------------------
    # Architecture summary
    # ------------------------------------------------------------------
    _section("ARCHITECTURE SUMMARY")
    _print("  Agent A (banking-publisher)")
    _print("      ↓  publish_package  →  ALLOW  →  stored  ✓")
    _print("  Fake Artifactory (shared repository)")
    _print("      ↓  read_package     →  ALLOW  →  received  ✓")
    _print("  Agent B (banking-reader)")
    _print()
    _print("  Cross-agent enforcement:")
    _print("    banking-reader  + publish_package  →  DENY  ✓")
    _print("    banking-publisher + read_package   →  DENY  ✓")
    _print()
    _print("  Key properties:")
    _print("    Agent A and Agent B do NOT communicate directly.")
    _print("    The Fake Artifactory is the ONLY shared channel.")
    _print("    Package content is returned as inert data — never executed.")
    _print("    Authorization is checked BEFORE any HTTP call is made.")
    _print()


if __name__ == "__main__":
    run_demo()
