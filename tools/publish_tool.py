"""
Publish Tool for Agent Security Lab.

Makes HTTP calls to the local Fake Artifactory service to publish packages.

Security properties
-------------------
- The tool does NOT execute package content.
- The message/content parameter is treated as inert text only.
- No credentials, API keys, or secrets are accepted or logged.
- The Artifactory URL defaults to http://127.0.0.1:8081 and must never
  silently switch to an external URL.

Audit logging
-------------
Every invocation emits a structured [AUDIT] line (matching the existing
banking_tools.py convention) capturing:
    agent_id, user_id (if present), tool, action, target,
    authorization_decision, reason, success/failure.
Secrets, cookies, and tokens are never included.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("agent-security-lab.tools")

# ---------------------------------------------------------------------------
# Package name validation — matches fake Artifactory's own rules
# ---------------------------------------------------------------------------
_VALID_PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _is_valid_package_name(package_name: str) -> bool:
    """Return True only if the package name is safe and non-empty."""
    if not package_name:
        return False
    if ".." in package_name or "/" in package_name or "\\" in package_name:
        return False
    return bool(_VALID_PACKAGE_NAME_RE.fullmatch(package_name))


# ---------------------------------------------------------------------------
# Audit log helper (same structure as banking_tools._audit)
# ---------------------------------------------------------------------------
def _audit(
    *,
    agent_id: str,
    user_id: Optional[str],
    tool: str,
    action: str,
    repository: str,
    package_name: str,
    target: str,
    authorization_decision: str,
    reason: str,
    outcome: str,
) -> None:
    """
    Emit a structured audit log line.
    Secrets, tokens, passwords, and cookies are NEVER included.

    Terminology
    -----------
    repository  – the target service/store (e.g. "fake-artifactory-local")
    package_name – the artefact within that store (e.g. "agent-message")
    target       – the full HTTP URL reached (or would have been reached)
    """
    logger.info(
        "[AUDIT] "
        "timestamp=%s "
        "agent_id=%s "
        "user_id=%s "
        "tool=%s "
        "action=%s "
        "repository=%s "
        "package_name=%s "
        "target=%s "
        "authorization_decision=%s "
        "reason=%s "
        "outcome=%s",
        datetime.now(timezone.utc).isoformat(),
        agent_id,
        user_id if user_id is not None else "N/A",
        tool,
        action,
        repository,
        package_name,
        target,
        authorization_decision,
        reason,
        outcome,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#: Default base URL for the local Fake Artifactory service.
DEFAULT_ARTIFACTORY_URL = "http://127.0.0.1:8081"

#: Allowed localhost base URLs.  The tool refuses to contact anything else.
_ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def _validate_artifactory_url(base_url: str) -> None:
    """Raise ValueError if base_url is not a localhost address."""
    import urllib.parse

    parsed = urllib.parse.urlparse(base_url)
    if parsed.hostname not in _ALLOWED_HOSTS:
        raise ValueError(
            f"publish_package tool refuses to contact non-localhost URL: '{base_url}'. "
            "Only 127.0.0.1 and localhost are permitted."
        )


def publish_package(
    *,
    agent_id: str,
    package_name: str,
    message: str,
    user_id: Optional[str] = None,
    repository: str = "fake-artifactory-local",
    artifactory_url: str = DEFAULT_ARTIFACTORY_URL,
) -> dict:
    """
    Publish a package to the local Fake Artifactory service.

    The ``message`` parameter is treated as plain text data.
    It is stored verbatim and is NEVER imported, evaluated, or executed.

    Args:
        agent_id:         Stable identifier of the calling agent.
        package_name:     Name of the package (alphanumeric, dashes, underscores).
        message:          Text content to store.  Inert data — never executed.
        user_id:          Optional principal/user identifier for audit trail.
        repository:       Logical name of the target repository (audit/tracing).
                          Defaults to "fake-artifactory-local".
        artifactory_url:  Base URL of the Fake Artifactory service.
                          Must be a localhost address.

    Returns:
        dict with keys:
            "success"     – bool
            "package"     – stored package dict (name, content, published_at)
                            or None on failure
            "error"       – error message string or None

    Raises:
        ValueError: if package_name is invalid or artifactory_url is external.
    """
    tool = "publish_package"
    action = "publish"

    # ------------------------------------------------------------------
    # 1. Validate the Artifactory URL — refuse external addresses
    # ------------------------------------------------------------------
    _validate_artifactory_url(artifactory_url)
    target = f"{artifactory_url}/packages/{package_name}"

    # ------------------------------------------------------------------
    # 2. Validate the package name locally before sending anything
    # ------------------------------------------------------------------
    if not _is_valid_package_name(package_name):
        _audit(
            agent_id=agent_id,
            user_id=user_id,
            tool=tool,
            action=action,
            repository=repository,
            package_name=package_name,
            target=target,
            authorization_decision="N/A",
            reason="Invalid package name rejected before HTTP call",
            outcome="FAILURE – invalid_package_name",
        )
        raise ValueError(
            f"Invalid package name '{package_name}'. "
            "Only alphanumeric characters, dashes, and underscores are allowed."
        )

    # ------------------------------------------------------------------
    # 3. POST to Fake Artifactory
    # ------------------------------------------------------------------
    try:
        resp = requests.post(
            target,
            json={"content": message},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.exceptions.ConnectionError as exc:
        _audit(
            agent_id=agent_id,
            user_id=user_id,
            tool=tool,
            action=action,
            repository=repository,
            package_name=package_name,
            target=target,
            authorization_decision="ALLOWED",
            reason="Agent is authorized; HTTP call failed",
            outcome=f"FAILURE – connection_error: {exc}",
        )
        return {"success": False, "package": None, "error": f"Connection error: {exc}"}

    # ------------------------------------------------------------------
    # 4. Interpret response
    # ------------------------------------------------------------------
    if resp.status_code == 201:
        data = resp.json()
        stored = data.get("package", {})
        _audit(
            agent_id=agent_id,
            user_id=user_id,
            tool=tool,
            action=action,
            repository=repository,
            package_name=package_name,
            target=target,
            authorization_decision="ALLOWED",
            reason="Agent is authorized to publish",
            outcome="SUCCESS",
        )
        return {"success": True, "package": stored, "error": None}

    # Non-201 response from Artifactory
    error_msg = resp.json().get("error", f"HTTP {resp.status_code}")
    _audit(
        agent_id=agent_id,
        user_id=user_id,
        tool=tool,
        action=action,
        repository=repository,
        package_name=package_name,
        target=target,
        authorization_decision="ALLOWED",
        reason="Agent is authorized; Artifactory returned an error",
        outcome=f"FAILURE – {error_msg}",
    )
    return {"success": False, "package": None, "error": error_msg}
