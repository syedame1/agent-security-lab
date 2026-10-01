"""
Banking Tools for Agent Security Lab.
Makes real HTTP calls to the running Legacy Netbanking application.

Endpoints
---------
POST /login.do                           – authenticate, obtain JSESSIONID
GET  /accountSummary.do                  – list accounts for the logged-in user
GET  /transactionHistory.do?accountId=N  – transactions for a numeric account id

Security modes
--------------
SECURE   – account ownership is verified against /accountSummary.do BEFORE
           calling /transactionHistory.do.  Unauthorised requests never reach
           the legacy application.
INSECURE – account_id is forwarded directly; no ownership check is performed.
           Exists only for the controlled BOLA security experiment.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("agent-security-lab.tools")

# ---------------------------------------------------------------------------
# Legacy Netbanking base URL
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:8080/legacy-netbanking"

# ---------------------------------------------------------------------------
# Session state (one shared requests.Session per login)
# ---------------------------------------------------------------------------
_session: Optional[requests.Session] = None
_authenticated_user: Optional[str] = None


# ---------------------------------------------------------------------------
# Audit log helper
# ---------------------------------------------------------------------------
def _audit(
    *,
    agent_id: str,
    user_id: str,
    tool: str,
    account_id: Optional[str],
    security_mode: str,
    target: str,
    authorization_result: str,
    application_result: str,
) -> None:
    """
    Emits a single structured audit log line.
    Passwords, cookies, and session tokens are never included.
    """
    logger.info(
        "[AUDIT] "
        "timestamp=%s "
        "agent_id=%s "
        "user_id=%s "
        "tool=%s "
        "account_id=%s "
        "security_mode=%s "
        "target=%s "
        "authorization_result=%s "
        "application_result=%s",
        datetime.now(timezone.utc).isoformat(),
        agent_id,
        user_id,
        tool,
        account_id if account_id is not None else "N/A",
        security_mode,
        target,
        authorization_result,
        application_result,
    )


# ---------------------------------------------------------------------------
# HTML parsers
# ---------------------------------------------------------------------------
def _parse_account_summary(html: str) -> dict:
    """
    Parse /accountSummary.do HTML into:
      { "account_number": { "id": int, "balance": str }, ... }

    The account select widget on /transactionHistory.do renders:
      <option value="2">ACC1001 (5000)</option>
    We use that because accountSummary.do only shows account_number + balance
    (no numeric id).  We therefore call transactionHistory.do without an
    accountId to get the full <select> which maps numeric id → account_number.
    """
    soup = BeautifulSoup(html, "html.parser")
    accounts = {}
    rows = soup.find_all("tr")
    for row in rows:
        cells = row.find_all("td")
        if len(cells) >= 2:
            acc_num = cells[0].get_text(strip=True)
            balance = cells[1].get_text(strip=True)
            # Skip header-like rows and the "Total" row
            if acc_num and not acc_num.lower().startswith("total") and re.match(r"[A-Z]", acc_num):
                accounts[acc_num] = {"balance": balance}
    return accounts


def _parse_account_id_map(html: str) -> dict:
    """
    Parse the <select name="accountId"> widget on /transactionHistory.do
    to build a mapping  account_number → numeric_id.

    Example option: <option value="2">ACC1001 (5000)</option>
    Returns: { "ACC1001": "2", "ACC1002": "3" }
    """
    soup = BeautifulSoup(html, "html.parser")
    mapping = {}
    select = soup.find("select", {"name": "accountId"})
    if select:
        for opt in select.find_all("option"):
            val = opt.get("value", "").strip()
            text = opt.get_text(strip=True)
            if val:
                # text is like "ACC1001 (5000)" – grab the account number token
                acc_num = text.split()[0]
                mapping[acc_num] = val
    return mapping


def _parse_transactions(html: str) -> list:
    """
    Parse the transaction table from /transactionHistory.do HTML.
    Returns a list of dicts with keys: date, from_account, to_account,
    amount, description.
    """
    soup = BeautifulSoup(html, "html.parser")
    transactions = []
    table = soup.find("table", {"class": "data-table"})
    if not table:
        return transactions
    rows = table.find_all("tr")
    for row in rows[1:]:           # skip header row
        cells = row.find_all("td")
        if len(cells) == 5:
            transactions.append({
                "date":         cells[0].get_text(strip=True),
                "from_account": cells[1].get_text(strip=True),
                "to_account":   cells[2].get_text(strip=True),
                "amount":       cells[3].get_text(strip=True),
                "description":  cells[4].get_text(strip=True),
            })
    return transactions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def login(username: str, password: str) -> bool:
    """
    POST to /login.do and store the resulting JSESSIONID in the module-level
    requests.Session.  The password is never logged.

    Returns True on success, False on failure.
    """
    global _session, _authenticated_user

    _session = requests.Session()
    url = f"{BASE_URL}/login.do"

    logger.info("Authenticating user '%s' against %s", username, url)

    resp = _session.post(
        url,
        data={"username": username, "password": password},
        allow_redirects=True,
        timeout=10,
    )

    # A successful login redirects to accountSummary.do (200 after redirect).
    # A failed login stays on /login.do and typically contains "Invalid".
    if resp.status_code == 200 and "login" not in resp.url.lower():
        _authenticated_user = username
        logger.info("Login succeeded for user '%s'", username)
        return True

    logger.warning("Login failed for user '%s' (status=%s, url=%s)", username, resp.status_code, resp.url)
    _session = None
    _authenticated_user = None
    return False


def get_account_summary(
    *,
    agent_id: str,
    user_id: str,
    security_mode: str,
) -> dict:
    """
    GET /accountSummary.do using the authenticated session.
    Returns a dict:
      { "user_id": str, "accounts": { acc_num: {"balance": str}, ... } }
    """
    if _session is None:
        raise RuntimeError("Not authenticated. Call login() first.")

    target = f"{BASE_URL}/accountSummary.do"
    resp = _session.get(target, timeout=10)
    resp.raise_for_status()

    accounts = _parse_account_summary(resp.text)

    _audit(
        agent_id=agent_id,
        user_id=user_id,
        tool="get_account_summary",
        account_id=None,
        security_mode=security_mode,
        target=target,
        authorization_result="ALLOWED",
        application_result=f"returned {len(accounts)} account(s)",
    )

    return {"user_id": user_id, "accounts": accounts}


def get_transaction_history(
    *,
    agent_id: str,
    user_id: str,
    account_id: str,
    security_mode: str,
) -> list:
    """
    Fetch transactions for account_id from the legacy application.

    SECURE mode
    -----------
    1. Fetch /accountSummary.do to obtain the authenticated user's accounts.
    2. Resolve account_id (may be numeric like "2" or alphanumeric like "ACC1001")
       against that list.
    3. If not found, log the denial and raise PermissionError without ever
       contacting /transactionHistory.do.

    INSECURE mode
    -------------
    Forward account_id (resolved to numeric if needed) directly to
    /transactionHistory.do without any ownership check.
    """
    if _session is None:
        raise RuntimeError("Not authenticated. Call login() first.")

    # ------------------------------------------------------------------
    # Step 1: resolve account_id → numeric id and account_number
    # We call /transactionHistory.do (no accountId param) to get the
    # <select> widget which maps numeric id → account_number for THIS user.
    # ------------------------------------------------------------------
    tx_base = f"{BASE_URL}/transactionHistory.do"
    sel_resp = _session.get(tx_base, timeout=10)
    sel_resp.raise_for_status()
    user_id_map = _parse_account_id_map(sel_resp.text)
    # user_id_map: { "ACC1001": "2", "ACC1002": "3" } – only user1's accounts

    # Build the reverse map: numeric_id → account_number
    num_to_name = {v: k for k, v in user_id_map.items()}

    # Normalise the requested account_id
    # Accept either "ACC1001" (account number) or "2" (numeric id)
    requested_numeric: Optional[str] = None
    requested_accnum: Optional[str] = None

    if account_id in user_id_map:
        # Caller supplied an account number that belongs to this user
        requested_accnum = account_id
        requested_numeric = user_id_map[account_id]
    elif account_id in num_to_name:
        # Caller supplied a numeric id that belongs to this user
        requested_numeric = account_id
        requested_accnum = num_to_name[account_id]
    else:
        # account_id is either a foreign numeric id or unknown account number
        # Treat it as a raw numeric id (the BOLA case)
        requested_numeric = account_id
        requested_accnum = None  # not found in user's list

    # ------------------------------------------------------------------
    # Step 2: SECURE mode – ownership verification
    # ------------------------------------------------------------------
    if security_mode == "SECURE":
        if requested_accnum is None:
            # account_id not found in this user's account list
            _audit(
                agent_id=agent_id,
                user_id=user_id,
                tool="get_transaction_history",
                account_id=account_id,
                security_mode=security_mode,
                target="N/A – blocked before legacy application was called",
                authorization_result="DENIED",
                application_result="N/A",
            )
            logger.warning(
                "AUTHORIZATION DENIED: user_id='%s' does not own account_id='%s'. "
                "Legacy application was NOT called.",
                user_id,
                account_id,
            )
            raise PermissionError(
                f"Access Denied: account_id '{account_id}' does not belong to user '{user_id}'"
            )

    # ------------------------------------------------------------------
    # Step 3: call legacy application
    # ------------------------------------------------------------------
    target_url = f"{tx_base}?accountId={requested_numeric}"
    resp = _session.get(target_url, timeout=10)
    resp.raise_for_status()
    transactions = _parse_transactions(resp.text)

    _audit(
        agent_id=agent_id,
        user_id=user_id,
        tool="get_transaction_history",
        account_id=account_id,
        security_mode=security_mode,
        target=target_url,
        authorization_result="ALLOWED",
        application_result=f"returned {len(transactions)} transaction(s)",
    )

    return transactions
