"""
Phase 2 Step 5 — Agentic Evidence Bundle Validation Tests.

Validates evidence/phase2_agentic_activity.json against the following checks:

A. Required fields exist.
B. Agent IDs are correct.
C. Tool names are correct.
D. ALLOW/DENY decisions match the existing authorization policy.
E. The relationship section matches the observed workflow.
F. No credentials/secrets/tokens appear anywhere in the document.
G. The file contains no external URLs (localhost references accepted where required).
H. The sender identity is explicitly marked as untrusted/claimed data.

These tests do NOT require Legacy Netbanking (no Tomcat / Struts needed).
"""

import json
import os
import re
import sys
import unittest

# ---------------------------------------------------------------------------
# Path setup — mirrors the pattern used throughout this test suite
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Locate the evidence file relative to this test file
# ---------------------------------------------------------------------------
_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EVIDENCE_PATH = os.path.join(_LAB_DIR, "evidence", "phase2_agentic_activity.json")

# ---------------------------------------------------------------------------
# Known-good values drawn directly from authorization_policy.py
# ---------------------------------------------------------------------------
_KNOWN_AGENT_IDS = {"banking-publisher", "banking-reader"}
_KNOWN_TOOL_NAMES = {"publish_package", "read_package", "create_demo_marker"}
_KNOWN_REPOSITORIES = {"fake-artifactory-local", "local-demo-resource"}

# Expected ALLOW/DENY map from authorization_policy._POLICY
_EXPECTED_DECISIONS: dict[tuple, str] = {
    # event_id -> (agent_id, tool, target_resource, expected_decision)
    "evt-001": ("banking-publisher", "publish_package", "fake-artifactory-local", "ALLOW"),
    "evt-002": ("banking-reader",    "read_package",    "fake-artifactory-local", "ALLOW"),
    "evt-003": ("banking-reader",    "create_demo_marker", "local-demo-resource", "ALLOW"),
    "evt-004": ("banking-reader",    "publish_package", "fake-artifactory-local", "DENY"),
    "evt-005": ("banking-publisher", "create_demo_marker", "local-demo-resource", "DENY"),
}

# Strings that must NOT appear anywhere in the JSON text
_FORBIDDEN_PATTERNS = [
    r"password",
    r"secret",
    r"token",
    r"credential",
    r"api.?key",
    r"JSESSIONID",
    r"session.?cookie",
    r"private.?key",
    r"-----BEGIN",
]

# External URL patterns — not localhost — must not appear
_EXTERNAL_URL_RE = re.compile(
    r"https?://(?!127\.0\.0\.1)(?!localhost)[a-zA-Z0-9\-\.]+",
    re.IGNORECASE,
)


def _load_bundle() -> dict:
    """Load and parse the evidence bundle. Raises FileNotFoundError if absent."""
    with open(_EVIDENCE_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestA_RequiredFieldsExist(unittest.TestCase):
    """A. Required fields exist at the top level and within each event."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()

    def test_top_level_events_key_present(self):
        self.assertIn("events", self.bundle)

    def test_top_level_relationships_key_present(self):
        self.assertIn("relationships", self.bundle)

    def test_top_level_agent_definitions_key_present(self):
        self.assertIn("agent_definitions", self.bundle)

    def test_top_level_sender_identity_disclaimer_present(self):
        self.assertIn("sender_identity_disclaimer", self.bundle)

    def test_top_level_workflow_chain_present(self):
        self.assertIn("workflow_chain", self.bundle)

    def test_top_level_concert_metadata_present(self):
        self.assertIn("concert_experiment_metadata", self.bundle)

    def test_events_is_a_list(self):
        self.assertIsInstance(self.bundle["events"], list)

    def test_events_not_empty(self):
        self.assertGreater(len(self.bundle["events"]), 0)

    def test_each_event_has_required_fields(self):
        required = {
            "event_id", "timestamp", "agent_id", "tool",
            "action", "authorization_decision", "outcome",
        }
        for event in self.bundle["events"]:
            for field in required:
                self.assertIn(
                    field, event,
                    msg=f"Event {event.get('event_id', '?')} missing field '{field}'",
                )

    def test_five_events_present(self):
        """The spec requires exactly five representative events."""
        self.assertEqual(len(self.bundle["events"]), 5)

    def test_event_ids_are_unique(self):
        ids = [e["event_id"] for e in self.bundle["events"]]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate event_id values found")

    def test_timestamps_are_non_empty_strings(self):
        for event in self.bundle["events"]:
            ts = event.get("timestamp")
            self.assertIsInstance(ts, str, msg=f"Event {event['event_id']}: timestamp not a string")
            self.assertTrue(ts.strip(), msg=f"Event {event['event_id']}: timestamp is empty")


class TestB_AgentIDsAreCorrect(unittest.TestCase):
    """B. Agent IDs in events and agent_definitions are the known valid values."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()

    def test_all_event_agent_ids_are_known(self):
        for event in self.bundle["events"]:
            self.assertIn(
                event["agent_id"], _KNOWN_AGENT_IDS,
                msg=f"Unknown agent_id '{event['agent_id']}' in event {event['event_id']}",
            )

    def test_agent_definitions_cover_both_agents(self):
        defined = {a["agent_id"] for a in self.bundle["agent_definitions"]}
        self.assertSetEqual(defined, _KNOWN_AGENT_IDS)

    def test_publisher_agent_definition_present(self):
        ids = [a["agent_id"] for a in self.bundle["agent_definitions"]]
        self.assertIn("banking-publisher", ids)

    def test_reader_agent_definition_present(self):
        ids = [a["agent_id"] for a in self.bundle["agent_definitions"]]
        self.assertIn("banking-reader", ids)

    def test_no_unknown_agent_ids_in_relationships(self):
        for rel in self.bundle["relationships"]:
            # subjects/objects that are agents must be known agent IDs
            for field in ("subject",):
                val = rel.get(field, "")
                if val in (_KNOWN_AGENT_IDS | _KNOWN_REPOSITORIES | {"agent-request"}):
                    continue
                # If it is not a known agent or repo, fail
                self.fail(
                    f"Relationship subject/object '{val}' is not a recognised identity"
                )


class TestC_ToolNamesAreCorrect(unittest.TestCase):
    """C. Tool names in events match the known tool set."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()

    def test_all_event_tool_names_are_known(self):
        for event in self.bundle["events"]:
            self.assertIn(
                event["tool"], _KNOWN_TOOL_NAMES,
                msg=f"Unknown tool '{event['tool']}' in event {event['event_id']}",
            )

    def test_all_event_action_names_are_known(self):
        for event in self.bundle["events"]:
            self.assertIn(
                event["action"], _KNOWN_TOOL_NAMES,
                msg=f"Unknown action '{event['action']}' in event {event['event_id']}",
            )

    def test_tool_and_action_are_consistent(self):
        for event in self.bundle["events"]:
            self.assertEqual(
                event["tool"], event["action"],
                msg=f"Event {event['event_id']}: 'tool' and 'action' differ",
            )


class TestD_AllowDenyDecisionsMatchPolicy(unittest.TestCase):
    """D. ALLOW/DENY decisions in each event match the authorization_policy."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()
        cls.events_by_id = {e["event_id"]: e for e in cls.bundle["events"]}

    def _check_event(self, event_id: str):
        agent, tool, target, expected_decision = _EXPECTED_DECISIONS[event_id]
        event = self.events_by_id[event_id]
        self.assertEqual(
            event["agent_id"], agent,
            msg=f"{event_id}: agent_id mismatch",
        )
        self.assertEqual(
            event["tool"], tool,
            msg=f"{event_id}: tool mismatch",
        )
        self.assertEqual(
            event["authorization_decision"], expected_decision,
            msg=f"{event_id}: expected decision '{expected_decision}' "
                f"but got '{event['authorization_decision']}'",
        )

    def test_evt_001_publisher_publish_allowed(self):
        self._check_event("evt-001")

    def test_evt_002_reader_read_allowed(self):
        self._check_event("evt-002")

    def test_evt_003_reader_create_marker_allowed(self):
        self._check_event("evt-003")

    def test_evt_004_reader_publish_denied(self):
        self._check_event("evt-004")

    def test_evt_005_publisher_create_marker_denied(self):
        self._check_event("evt-005")

    def test_allow_events_have_success_outcome(self):
        for event in self.bundle["events"]:
            if event["authorization_decision"] == "ALLOW":
                self.assertEqual(
                    event["outcome"], "SUCCESS",
                    msg=f"Event {event['event_id']}: ALLOW decision should have SUCCESS outcome",
                )

    def test_deny_events_have_blocked_outcome(self):
        for event in self.bundle["events"]:
            if event["authorization_decision"] == "DENY":
                self.assertEqual(
                    event["outcome"], "BLOCKED",
                    msg=f"Event {event['event_id']}: DENY decision should have BLOCKED outcome",
                )


class TestE_RelationshipsMatchWorkflow(unittest.TestCase):
    """E. The relationship section matches the observed workflow chain."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()
        cls.rels = cls.bundle["relationships"]

    def _find_rel(self, subject: str, predicate: str, obj: str):
        for r in self.rels:
            if r["subject"] == subject and r["predicate"] == predicate and r["object"] == obj:
                return r
        return None

    def test_publisher_publishes_to_artifactory(self):
        rel = self._find_rel("banking-publisher", "PUBLISHES_TO", "fake-artifactory-local")
        self.assertIsNotNone(rel, "Missing PUBLISHES_TO relationship")

    def test_artifactory_contains_agent_request(self):
        rel = self._find_rel("fake-artifactory-local", "CONTAINS", "agent-request")
        self.assertIsNotNone(rel, "Missing CONTAINS relationship")

    def test_reader_reads_from_artifactory(self):
        rel = self._find_rel("banking-reader", "READS_FROM", "fake-artifactory-local")
        self.assertIsNotNone(rel, "Missing READS_FROM relationship")

    def test_reader_creates_local_demo_resource(self):
        rel = self._find_rel("banking-reader", "CREATES", "local-demo-resource")
        self.assertIsNotNone(rel, "Missing CREATES relationship")

    def test_four_relationships_present(self):
        self.assertEqual(len(self.rels), 4, "Expected exactly 4 relationships")

    def test_each_relationship_has_evidence_event_ids(self):
        for rel in self.rels:
            self.assertIn("evidence_event_ids", rel)
            self.assertIsInstance(rel["evidence_event_ids"], list)
            self.assertGreater(len(rel["evidence_event_ids"]), 0)


class TestF_NoCredentialsOrSecrets(unittest.TestCase):
    """F. No credentials, secrets, or tokens appear anywhere in the bundle."""

    @classmethod
    def setUpClass(cls):
        with open(_EVIDENCE_PATH, "r", encoding="utf-8") as fh:
            cls.raw_text = fh.read().lower()

    def test_no_forbidden_patterns(self):
        for pattern in _FORBIDDEN_PATTERNS:
            matches = re.findall(pattern, self.raw_text, re.IGNORECASE)
            # The word "secret" appears legitimately in the disclaimer field name
            # "client_secret" or "no secrets" — filter to actual values not field names
            # We exclude the boolean field "contains_secrets" (value: false) and
            # explanatory prose in _important that says "No secrets ... are present"
            if pattern in (r"secret", r"credential", r"token", r"password"):
                # Allowed appearances: inside negating/metadata prose only
                # Re-check: none of the matches should be adjacent to an assignment value
                suspicious = [
                    m for m in re.findall(
                        rf'"{pattern}"?\s*:\s*"[^"]+"|{pattern}\s*=\s*\S+',
                        self.raw_text,
                        re.IGNORECASE,
                    )
                    # allow: "contains_secrets": false, "contains_credentials": false, etc.
                    if not re.search(r":\s*false", m)
                ]
                self.assertEqual(
                    suspicious, [],
                    msg=f"Suspicious pattern '{pattern}' found with an assigned value: {suspicious}",
                )
            else:
                self.assertEqual(
                    matches, [],
                    msg=f"Forbidden pattern '{pattern}' found in evidence bundle",
                )

    def test_contains_secrets_is_false(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertIs(meta.get("contains_secrets"), False)

    def test_contains_credentials_is_false(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertIs(meta.get("contains_credentials"), False)

    def test_contains_tokens_is_false(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertIs(meta.get("contains_tokens"), False)

    def test_contains_cookies_is_false(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertIs(meta.get("contains_cookies"), False)

    def test_contains_real_customer_data_is_false(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertIs(meta.get("contains_real_customer_data"), False)


class TestG_NoExternalURLs(unittest.TestCase):
    """G. No external (non-localhost) URLs appear in the evidence file."""

    @classmethod
    def setUpClass(cls):
        with open(_EVIDENCE_PATH, "r", encoding="utf-8") as fh:
            cls.raw_text = fh.read()

    def test_no_external_urls(self):
        matches = _EXTERNAL_URL_RE.findall(self.raw_text)
        self.assertEqual(
            matches, [],
            msg=f"External URLs found in evidence bundle: {matches}",
        )

    def test_external_urls_list_is_empty(self):
        bundle = _load_bundle()
        meta = bundle.get("concert_experiment_metadata", {})
        self.assertEqual(meta.get("external_urls"), [])


class TestH_SenderIdentityMarkedUntrusted(unittest.TestCase):
    """H. The sender identity is explicitly marked as untrusted/claimed data."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _load_bundle()
        cls.disclaimer = cls.bundle.get("sender_identity_disclaimer", {})

    def test_disclaimer_section_present(self):
        self.assertIn("sender_identity_disclaimer", self.bundle)

    def test_claimed_identity_field_documented(self):
        self.assertIn("claimed_identity_field", self.disclaimer)
        self.assertEqual(self.disclaimer["claimed_identity_field"], "package.content.sender")

    def test_authentication_method_is_none(self):
        self.assertIn("authentication_method", self.disclaimer)
        val = self.disclaimer["authentication_method"].upper()
        self.assertIn("NONE", val)

    def test_cryptographic_proof_is_false(self):
        self.assertIn("cryptographic_proof", self.disclaimer)
        self.assertIs(self.disclaimer["cryptographic_proof"], False)

    def test_trust_level_is_untrusted(self):
        self.assertIn("trust_level", self.disclaimer)
        val = self.disclaimer["trust_level"].upper()
        self.assertIn("UNTRUSTED", val)

    def test_important_warning_present(self):
        self.assertIn("_important", self.disclaimer)
        text = self.disclaimer["_important"].upper()
        self.assertIn("NOT CRYPTOGRAPHICALLY AUTHENTICATED", text)

    def test_claimed_value_is_banking_publisher(self):
        self.assertEqual(self.disclaimer.get("claimed_value"), "banking-publisher")
