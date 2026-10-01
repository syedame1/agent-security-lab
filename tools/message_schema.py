"""
Benign Message Schema — Phase 2 Step 4.

Defines the structured data format for inter-agent demo requests and
provides strict validation of incoming messages.

Message format
--------------
{
    "sender":           "banking-publisher",
    "message_type":     "demo_request",
    "requested_action": "create_demo_marker",
    "marker_name":      "marker-001"
}

Security design
---------------
- JSON is parsed as DATA only — never executed.
- requested_action is checked against a HARD-CODED allowlist of exactly one
  entry: "create_demo_marker".
- Any other value for requested_action produces an explicit REJECT result.
- marker_name is validated before being passed to the tool.
- Unknown or extra keys do not cause failures, but they produce a warning.
"""

import json
import logging
import re
from typing import Optional

logger = logging.getLogger("agent-security-lab.message_schema")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPECTED_SENDER = "banking-publisher"
EXPECTED_MESSAGE_TYPE = "demo_request"

# Hard-coded allowlist — the ONLY action Agent B may act upon.
# This is NOT dynamic.  New actions require explicit code changes.
_ALLOWED_ACTIONS: frozenset[str] = frozenset({"create_demo_marker"})

# Required top-level fields in a valid demo_request message
_REQUIRED_FIELDS = ("sender", "message_type", "requested_action", "marker_name")

# Marker name validation (same rules as demo_marker_tool)
_VALID_MARKER_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _is_valid_marker_name(marker_name: str) -> bool:
    """Return True only if the marker name is safe and non-empty."""
    if not marker_name:
        return False
    if ".." in marker_name or "/" in marker_name or "\\" in marker_name:
        return False
    return bool(_VALID_MARKER_NAME_RE.fullmatch(marker_name))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_demo_request(raw_content: str) -> dict:
    """
    Parse and validate a demo_request message from raw string content.

    The content is treated as DATA.  It is parsed with json.loads() and
    the resulting dict is inspected field-by-field.  No field value is
    executed, imported, or evaluated as code.

    Args:
        raw_content: The raw string retrieved from the package's "content"
                     field.

    Returns:
        dict with keys:
            "valid"            – bool
            "requested_action" – str or None (only if valid)
            "marker_name"      – str or None (only if valid)
            "sender"           – str or None
            "message_type"     – str or None
            "reject_reason"    – str or None (only if not valid)

    The returned dict is NEVER executed — callers must consult "valid" and
    then act only on the allowed "requested_action" value via an explicit
    dispatch table.
    """
    # ------------------------------------------------------------------
    # 1. Parse JSON — failure → reject
    # ------------------------------------------------------------------
    try:
        payload = json.loads(raw_content)
    except (json.JSONDecodeError, TypeError) as exc:
        reason = f"Content is not valid JSON: {exc}"
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason)

    if not isinstance(payload, dict):
        reason = "Parsed JSON is not an object/dict"
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason)

    # ------------------------------------------------------------------
    # 2. Check required fields are present
    # ------------------------------------------------------------------
    for field in _REQUIRED_FIELDS:
        if field not in payload:
            reason = f"Missing required field: '{field}'"
            logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
            return _reject(reason)

    sender: str = str(payload["sender"])
    message_type: str = str(payload["message_type"])
    requested_action: str = str(payload["requested_action"])
    marker_name: str = str(payload["marker_name"])

    # ------------------------------------------------------------------
    # 3. Verify sender and message_type
    # ------------------------------------------------------------------
    if sender != EXPECTED_SENDER:
        reason = f"Unexpected sender '{sender}' (expected '{EXPECTED_SENDER}')"
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason, sender=sender, message_type=message_type)

    if message_type != EXPECTED_MESSAGE_TYPE:
        reason = (
            f"Unexpected message_type '{message_type}' "
            f"(expected '{EXPECTED_MESSAGE_TYPE}')"
        )
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason, sender=sender, message_type=message_type)

    # ------------------------------------------------------------------
    # 4. Check requested_action against the EXPLICIT HARD-CODED allowlist
    #    This is NOT dynamic dispatch — only "create_demo_marker" is allowed.
    # ------------------------------------------------------------------
    if requested_action not in _ALLOWED_ACTIONS:
        reason = (
            f"requested_action '{requested_action}' is not in the allowlist "
            f"{sorted(_ALLOWED_ACTIONS)}. Action REJECTED."
        )
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason, sender=sender, message_type=message_type)

    # ------------------------------------------------------------------
    # 5. Validate the marker_name field
    # ------------------------------------------------------------------
    if not _is_valid_marker_name(marker_name):
        reason = (
            f"marker_name '{marker_name}' failed validation. "
            "Only alphanumeric characters, dashes, and underscores (1-64 chars) allowed. "
            "Path traversal characters are forbidden."
        )
        logger.warning("[MESSAGE_SCHEMA] REJECT – %s", reason)
        return _reject(reason, sender=sender, message_type=message_type)

    # ------------------------------------------------------------------
    # 6. All checks passed
    # ------------------------------------------------------------------
    logger.info(
        "[MESSAGE_SCHEMA] ACCEPT – sender=%s message_type=%s "
        "requested_action=%s marker_name=%s",
        sender, message_type, requested_action, marker_name,
    )
    return {
        "valid": True,
        "sender": sender,
        "message_type": message_type,
        "requested_action": requested_action,
        "marker_name": marker_name,
        "reject_reason": None,
    }


def _reject(
    reason: str,
    sender: Optional[str] = None,
    message_type: Optional[str] = None,
) -> dict:
    """Return a uniform rejection result dict."""
    return {
        "valid": False,
        "sender": sender,
        "message_type": message_type,
        "requested_action": None,
        "marker_name": None,
        "reject_reason": reason,
    }
