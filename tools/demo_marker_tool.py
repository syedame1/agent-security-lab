"""
Demo Marker Tool — Phase 2 Step 4.

Creates a harmless text file under demo_resources/ to demonstrate that
Agent B can perform exactly ONE explicitly predefined local action after
reading a structured data message from the shared repository.

Security properties
-------------------
- marker_name is strictly validated (alphanumeric, dashes, underscores only).
- Path traversal characters (/  \\  ..) are unconditionally rejected.
- The tool ONLY writes beneath the demo_resources/ directory.
- The marker_name is NEVER executed, eval'd, imported, or passed to a shell.
- No credentials, API keys, or secrets are accepted or logged.
- File contents are fixed — they are NOT derived from arbitrary input.

Audit logging
-------------
Every invocation emits a structured [AUDIT] line capturing:
    agent_id, tool, action, target, marker_name,
    authorization_decision, reason, outcome.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("agent-security-lab.tools")

# ---------------------------------------------------------------------------
# marker_name validation
# ---------------------------------------------------------------------------
_VALID_MARKER_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

_DEMO_RESOURCES_SUBDIR = "demo_resources"


def _is_valid_marker_name(marker_name: str) -> bool:
    """Return True only if the marker name is safe, non-empty, and short."""
    if not marker_name:
        return False
    # Reject any path traversal attempt at the character level
    if ".." in marker_name or "/" in marker_name or "\\" in marker_name:
        return False
    return bool(_VALID_MARKER_NAME_RE.fullmatch(marker_name))


def _get_demo_resources_dir(base_dir: Optional[str] = None) -> str:
    """
    Return the absolute path of the demo_resources/ directory.

    If base_dir is None, the directory is resolved relative to this
    source file, ensuring the path is always inside the lab tree.
    """
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.abspath(os.path.join(base_dir, _DEMO_RESOURCES_SUBDIR))


# ---------------------------------------------------------------------------
# Audit log helper
# ---------------------------------------------------------------------------
def _audit(
    *,
    agent_id: str,
    tool: str,
    action: str,
    target: str,
    marker_name: str,
    authorization_decision: str,
    reason: str,
    outcome: str,
) -> None:
    """Emit a structured audit log line. No secrets are ever included."""
    logger.info(
        "[AUDIT] "
        "timestamp=%s "
        "agent_id=%s "
        "tool=%s "
        "action=%s "
        "target=%s "
        "marker_name=%s "
        "authorization_decision=%s "
        "reason=%s "
        "outcome=%s",
        datetime.now(timezone.utc).isoformat(),
        agent_id,
        tool,
        action,
        target,
        marker_name,
        authorization_decision,
        reason,
        outcome,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_demo_marker(
    *,
    agent_id: str,
    marker_name: str,
    base_dir: Optional[str] = None,
) -> dict:
    """
    Create a harmless text file at demo_resources/<marker_name>.txt.

    The file content is entirely static — it does NOT incorporate the
    marker_name as executable code or a shell command.

    Args:
        agent_id:    Stable identifier of the calling agent.
        marker_name: Safe alphanumeric identifier (1-64 chars,
                     [a-zA-Z0-9_-] only).  Path traversal is rejected.
        base_dir:    Optional override for the lab root directory.
                     Defaults to the parent of this file's directory.

    Returns:
        dict with keys:
            "success"     – bool
            "marker_path" – absolute path of the created file, or None
            "error"       – error message string or None

    Raises:
        ValueError: if marker_name is invalid.
    """
    tool = "create_demo_marker"
    action = "create_marker"
    demo_dir = _get_demo_resources_dir(base_dir)
    target = os.path.join(demo_dir, f"{marker_name}.txt")

    # ------------------------------------------------------------------
    # 1. Validate marker_name — reject before any filesystem access
    # ------------------------------------------------------------------
    if not _is_valid_marker_name(marker_name):
        _audit(
            agent_id=agent_id,
            tool=tool,
            action=action,
            target=target,
            marker_name=marker_name,
            authorization_decision="N/A",
            reason="Invalid marker_name rejected before filesystem access",
            outcome="FAILURE – invalid_marker_name",
        )
        raise ValueError(
            f"Invalid marker_name '{marker_name}'. "
            "Only alphanumeric characters, dashes, and underscores (1-64 chars) are allowed."
        )

    # ------------------------------------------------------------------
    # 2. Verify the resolved path stays inside demo_resources/
    # ------------------------------------------------------------------
    resolved = os.path.abspath(target)
    if not resolved.startswith(demo_dir + os.sep) and resolved != demo_dir:
        _audit(
            agent_id=agent_id,
            tool=tool,
            action=action,
            target=target,
            marker_name=marker_name,
            authorization_decision="N/A",
            reason="Path traversal detected after resolution",
            outcome="FAILURE – path_traversal",
        )
        raise ValueError(f"Path traversal detected for marker_name '{marker_name}'.")

    # ------------------------------------------------------------------
    # 3. Create the demo_resources/ directory if needed
    # ------------------------------------------------------------------
    os.makedirs(demo_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # 4. Write the static marker file
    #    Contents are entirely fixed — marker_name is NOT executed.
    # ------------------------------------------------------------------
    file_contents = (
        f"created-by={agent_id}\n"
        f"marker={marker_name}\n"
        f"created-at={datetime.now(timezone.utc).isoformat()}\n"
    )

    with open(resolved, "w", encoding="utf-8") as fh:
        fh.write(file_contents)

    _audit(
        agent_id=agent_id,
        tool=tool,
        action=action,
        target=resolved,
        marker_name=marker_name,
        authorization_decision="ALLOWED",
        reason="Agent is authorized to create demo markers",
        outcome="SUCCESS",
    )
    return {"success": True, "marker_path": resolved, "error": None}
