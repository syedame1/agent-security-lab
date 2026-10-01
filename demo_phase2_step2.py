#!/usr/bin/env python3
"""
Phase 2 Step 2 — Agent A Package Publishing Demonstration.

Shows the complete publish flow:

    banking-publisher (Agent A)
        ↓
    publish_package("agent-message", "hello from Agent A")
        ↓
    authorization = ALLOW
        ↓
    Fake Artifactory
        ↓
    package stored
        ↓
    retrieve to prove persistence

Also demonstrates the DENY path:

    rogue-agent (NOT authorized)
        ↓
    publish_package  →  DENIED
        ↓
    Fake Artifactory is NEVER called

Usage
-----
1. Start the Fake Artifactory service in a separate terminal:

       cd agent-security-lab
       python3 -m fake_artifactory.service --port 8081

2. Run this script:

       cd agent-security-lab
       python3 demo_phase2_step2.py

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
from gateway.publish_gateway import PublishGateway

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("demo_phase2_step2")

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

    agent = BankingPublisherAgent()
    gateway = PublishGateway(artifactory_url=ARTIFACTORY_URL)

    # ------------------------------------------------------------------
    # DEMO 1 — ALLOW path
    # ------------------------------------------------------------------
    _section("DEMO 1 — ALLOW: banking-publisher publishes a package")

    _print(f"  Agent ID : {agent.agent_id}")
    _print(f"  Tool     : publish_package")
    _print(f"  Package  : agent-message")
    _print(f"  Message  : hello from Agent A")
    _print()

    decision = agent.decide_tool("agent-message", "hello from Agent A")
    _print(f"  Agent decision: {json.dumps(decision, indent=4)}")
    _print()

    context = {"agent_id": agent.agent_id, "user_id": "demo-user"}
    _print("  Calling gateway.execute_tool() ...")
    result = gateway.execute_tool(context, decision["tool_name"], decision["arguments"])

    _print()
    _print(f"  Result: {json.dumps(result, indent=4)}")

    if result["success"]:
        _print()
        _print("  authorization = ALLOW  ✓")
        _print("  Package stored in Fake Artifactory  ✓")
    else:
        _print(f"  UNEXPECTED FAILURE: {result['error']}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # DEMO 2 — Retrieve from Fake Artifactory to prove persistence
    # ------------------------------------------------------------------
    _section("DEMO 2 — Retrieve package to prove persistence")

    resp = requests.get(f"{ARTIFACTORY_URL}/packages/agent-message", timeout=5)
    if resp.status_code != 200:
        _print(f"  ERROR: GET returned {resp.status_code}")
        sys.exit(1)

    stored = resp.json()
    _print(f"  GET {ARTIFACTORY_URL}/packages/agent-message  →  HTTP 200  ✓")
    _print()
    _print(f"  Stored package:")
    _print(json.dumps(stored, indent=4))
    _print()
    _print("  Package name    : " + stored["name"])
    _print("  Package content : " + stored["content"])
    _print("  Published at    : " + stored["published_at"])

    # ------------------------------------------------------------------
    # DEMO 3 — DENY path: rogue agent
    # ------------------------------------------------------------------
    _section("DEMO 3 — DENY: rogue-agent is blocked before Artifactory is called")

    rogue_context = {"agent_id": "rogue-agent", "user_id": "attacker"}
    _print(f"  Agent ID : rogue-agent")
    _print(f"  Tool     : publish_package")
    _print()
    _print("  Calling gateway.execute_tool() ...")

    try:
        gateway.execute_tool(
            rogue_context,
            "publish_package",
            {"package_name": "evil-pkg", "message": "malicious content"},
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

    # Verify rogue package does NOT exist in Artifactory
    resp = requests.get(f"{ARTIFACTORY_URL}/packages/evil-pkg", timeout=5)
    assert resp.status_code == 404, f"Expected 404 but got {resp.status_code}"
    _print("  Confirmed: evil-pkg NOT present in Artifactory (HTTP 404)  ✓")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    _section("SUMMARY")
    _print("  banking-publisher  →  publish_package  →  ALLOW  →  stored  ✓")
    _print("  rogue-agent        →  publish_package  →  DENY   →  NOT reached  ✓")
    _print()
    _print("  Security model verified:")
    _print("    Agent A has publish permission ONLY.")
    _print("    Authorization is enforced BEFORE the shared service is reached.")
    _print("    Package content is stored as inert text — never executed.")
    _print()


if __name__ == "__main__":
    run_demo()
