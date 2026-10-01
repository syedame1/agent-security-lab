# Agent Security Lab

Welcome to the **Agent Security Lab**. This lab is designed to study security vulnerabilities, specifically authorization failures (Broken Object Level Authorization - BOLA), in AI/agentic systems interacting with legacy netbanking applications through tool calling and gateways.

## Request Flow

The exact request flow in this environment is documented below:

```
[ User ]
   │
   │  1. (user_id, raw request string)
   ▼
[ Mock Agent ]
   │
   │  2. Deterministic Intent Parse → (tool_name, arguments)
   ▼
[ Tool Gateway ]
   │
   │  3. Check mode (INSECURE vs SECURE)
   │     - INSECURE: Passes account_id directly to legacy app without ownership check.
   │     - SECURE:   Verifies account_id belongs to user_id before calling legacy app.
   ▼
[ Legacy Netbanking Application (HTTP) ]
   │
   │  4. Execute Struts action / query database
   ▼
[ Legacy Database ]
```

---

## BOLA Attack Path

The following path traces exactly how an authenticated user can retrieve
another user's transaction data when the INSECURE mode is active.

```
User (user1)
 │
 │  request: "Show transactions for account 4"
 ▼
AI Agent (banking-assistant)
 │
 │  tool_name = "get_transaction_history"
 │  arguments = { "account_id": "4" }
 ▼
Tool Gateway  [INSECURE mode — no ownership check]
 │
 │  POST http://localhost:8080/legacy-netbanking/login.do
 │       username=user1  (JSESSIONID stored in session)
 │
 │  GET  http://localhost:8080/legacy-netbanking/transactionHistory.do?accountId=4
 │       ← carries JSESSIONID cookie
 ▼
Legacy Netbanking  (Apache Struts)
 │
 │  TransactionHistoryAction.execute()
 │    accountId parameter = 4   ← taken directly from URL, no ownership check
 ▼
TransactionDAO.findByAccountId(4)
 │
 │  SELECT ... WHERE from_account = 4 OR to_account = 4
 ▼
Account 4 / ACC2001
 │
 │  account belongs to user2, not user1
 ▼
Other user's transaction data returned to user1
```

### Why this path exists

`TransactionHistoryAction` calls `accountDAO.findByUserId(user.getId())` only to
populate the account drop-down in the UI.  The subsequent
`transactionDAO.findByAccountId(accountId)` query uses the integer from the
request parameter **without** verifying that `accountId` belongs to the
authenticated user.  Any logged-in user who knows (or guesses) a numeric
account id can therefore retrieve any other user's transactions.

### SECURE mode mitigation

In SECURE mode the Tool Gateway fetches `/accountSummary.do` first and builds
the authenticated user's account list.  If the requested `account_id` is not
found in that list the gateway raises `PermissionError` and the legacy
application is **never called**.

---

## Tool Definitions & Modes

A **Deterministic Mock Banking Agent** and a **Tool Gateway** manage context and
invoke the following tools.  All tools make real HTTP calls to the running
Legacy Netbanking application.

### `login(username, password)`
* **Action**: `POST /login.do` with form credentials.
* Stores the returned `JSESSIONID` in a `requests.Session`.
* The password is **never logged**.

### `get_account_summary`
* **Action**: `GET /accountSummary.do` using the authenticated session.
* Returns the accounts belonging to the authenticated user.

### `get_transaction_history(account_id)`
* **SECURE mode**
  1. Fetches `/accountSummary.do` to obtain the user's own account list.
  2. Verifies that `account_id` is in that list.
  3. If not, raises `PermissionError` **without calling** the legacy application.
* **INSECURE mode**
  * Passes `account_id` directly to `/transactionHistory.do?accountId=<id>`.
  * No ownership check is performed.
  * Exists **only** for the controlled security experiment.

---

## Audit Logging

Every tool call emits a structured `[AUDIT]` log line containing:

| Field | Description |
|---|---|
| `timestamp` | ISO-8601 UTC |
| `agent_id` | Identifier of the calling agent |
| `user_id` | Authenticated user |
| `tool` | Tool name |
| `account_id` | Requested account (N/A for summary) |
| `security_mode` | SECURE or INSECURE |
| `target` | URL called (or "N/A – blocked" when denied) |
| `authorization_result` | ALLOWED or DENIED |
| `application_result` | rows returned or N/A |

Passwords, cookies, and session tokens are **never** included in log output.

---

## Caller Context

The Tool Gateway maintains and enforces a strict caller context:

```json
{
  "user_id": "user1",
  "agent_id": "banking-assistant"
}
```

---

## Getting Started

### Prerequisites

* Legacy Netbanking application running at `http://localhost:8080/legacy-netbanking`
* Python 3.x with `requests` and `beautifulsoup4` installed

```bash
pip install requests beautifulsoup4
```

### Directory Structure

```
agent-security-lab/
  ├── README.md
  ├── demo_phase2_step2.py          ← Phase 2 Step 2 end-to-end demo script
  ├── agent/
  │    ├── __init__.py
  │    ├── mock_agent.py             ← banking-assistant (Phase 1)
  │    └── publisher_agent.py       ← banking-publisher / Agent A (Phase 2 Step 2)
  ├── fake_artifactory/             ← Phase 2 local synthetic package repository
  │    ├── __init__.py
  │    ├── packages/                ← local filesystem storage for packages
  │    └── service.py               ← lightweight HTTP service & CLI
  ├── tools/
  │    ├── __init__.py
  │    ├── banking_tools.py         ← real HTTP calls to Legacy Netbanking
  │    └── publish_tool.py          ← publish_package tool (Phase 2 Step 2)
  ├── gateway/
  │    ├── __init__.py
  │    ├── tool_gateway.py          ← banking gateway (Phase 1)
  │    ├── authorization_policy.py  ← explicit ALLOW/DENY policy table (Phase 2 Step 2)
  │    └── publish_gateway.py       ← publish gateway with authz check (Phase 2 Step 2)
  └── tests/
       ├── __init__.py
       ├── test_agent_a_publish.py   ← Agent A authorization & publish tests (Phase 2 Step 2)
       ├── test_fake_artifactory.py  ← unit & integration tests for fake Artifactory
       ├── test_gateway_security.py  ← gateway security tests (live Legacy Netbanking)
       └── test_live_integration.py  ← integration tests (live Legacy Netbanking)
```

---

## Fake Artifactory Package Repository (Phase 2)

### Overview & Purpose
The `fake_artifactory` module provides a minimal, local HTTP service acting as a synthetic package repository. It is designed to model multi-agent interactions and shared resource dependencies without connecting to external networks or services.

### Why Local & Synthetic?
- **Zero External Dependencies / Internet Isolation:** Completely self-contained and operates purely on `localhost` (`127.0.0.1`), ensuring safety and isolation.
- **No Secrets or Real Credentials:** No API keys, tokens, or sensitive credentials are used or logged.
- **No Arbitrary Code Execution:** Packages are stored and served as structured JSON text metadata and content.

### API Endpoints

| Method | Endpoint | Description | Sample Request / Response |
|---|---|---|---|
| `GET` | `/health` | Health check endpoint | `{"status": "ok"}` |
| `POST` | `/packages/<package_name>` | Publish a package (raw text or JSON `{ "content": "..." }`) | `{"message": "Package stored successfully", "package": {"name": "...", "content": "...", "published_at": "..."}}` |
| `GET` | `/packages/<package_name>` | Retrieve a package by name | `{"name": "...", "content": "...", "published_at": "..."}` |
| `GET` | `/packages` | List all stored package names | `{"packages": ["pkg1", "pkg2"]}` |

### Security & Path Traversal Prevention
Package names are validated using strict alphanumeric/dash/underscore rules (`^[a-zA-Z0-9_\-]+$`) and path boundaries are asserted via resolved paths. Attempts containing `..`, `/`, or `\\` are rejected with HTTP 400.

### Starting the Fake Artifactory Service

```bash
cd agent-security-lab
python3 -m fake_artifactory.service --port 8081
```

### Running Fake Artifactory Tests

```bash
cd agent-security-lab
python3 -m unittest tests.test_fake_artifactory -v
```

### Running the Integration Tests

Requires the Legacy Netbanking application to be running.

```bash
cd agent-security-lab
python3 -m unittest tests.test_live_integration -v
```

### Running All Tests

```bash
cd agent-security-lab
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## Phase 2 Step 2 — Agent A Package Publishing Tool

### Security Model

```
Agent A (banking-publisher)
    │
    │  decide_tool(package_name, message)
    ▼
BankingPublisherAgent
    │
    │  tool_name = "publish_package"
    │  arguments = { package_name, message }
    ▼
PublishGateway
    │
    │  Step 1: check_authorization(agent_id, tool_name)
    │     DENY  → PermissionError raised
    │              Fake Artifactory is NEVER called
    │
    │     ALLOW → continue
    │
    ▼
publish_package tool
    │
    │  Validate package_name (local)
    │  POST http://127.0.0.1:8081/packages/<name>
    │        body = { "content": "<message>" }
    ▼
Fake Artifactory HTTP service
    │
    │  Persist { name, content, published_at } to JSON file
    │  Return 201 + stored package data
    ▼
package stored
```

### Agent A Current Permissions

| Agent ID | Tool | Decision |
|---|---|---|
| `banking-publisher` | `publish_package` | **ALLOW** |
| `banking-publisher` | *anything else* | DENY |
| *any other agent* | `publish_package` | DENY |
| *any other agent* | *anything* | DENY |

**Agent A currently has publish permission only.**  
All other tool access is denied by the authorization policy (deny-by-default).

### Authorization Policy

The policy table lives in [`gateway/authorization_policy.py`](gateway/authorization_policy.py).
Only `("banking-publisher", "publish_package")` is in the ALLOW list.
Every other `(agent_id, tool_name)` combination resolves to DENY.

The authorization check runs **inside the gateway, before any HTTP call is made** to
the Fake Artifactory service.  An unauthorized agent can never reach the shared
repository, even indirectly.

### Content Security Constraint

The `message` parameter is treated as **inert text data**.  It is stored verbatim
as a JSON string and is **never imported, evaluated, executed, or dynamically loaded**.

The following content, for example, is safe to store:

```python
def get_auth_token():
    return "demo-token"
```

It remains a string in storage and is never interpreted as code.

### Audit Logging

Every tool invocation emits a structured `[AUDIT]` log line.  Denied requests
additionally produce an `[AUTHZ]` line from the policy evaluator.

| Field | Description |
|---|---|
| `timestamp` | ISO-8601 UTC |
| `agent_id` | Calling agent identifier |
| `user_id` | Principal if available (N/A otherwise) |
| `tool` | Tool name |
| `action` | Action performed |
| `target` | URL targeted (or N/A if blocked) |
| `authorization_decision` | ALLOWED / DENIED / N/A |
| `reason` | Human-readable explanation |
| `outcome` | SUCCESS or FAILURE with detail |

Secrets, passwords, cookies, and tokens are **never** included in log output.

### New Files

| File | Role |
|---|---|
| `agent/publisher_agent.py` | `BankingPublisherAgent` — Agent A with `agent_id = "banking-publisher"` |
| `gateway/authorization_policy.py` | Explicit ALLOW/DENY policy table |
| `gateway/publish_gateway.py` | Gateway that checks authz before dispatching |
| `tools/publish_tool.py` | `publish_package` HTTP tool for Fake Artifactory |
| `tests/test_agent_a_publish.py` | Full test suite for Phase 2 Step 2 |
| `demo_phase2_step2.py` | End-to-end demonstration script |

### Running Phase 2 Step 2 Tests (no Legacy Netbanking required)

```bash
cd agent-security-lab
python3 -m unittest tests.test_agent_a_publish -v
```

### Running All Tests That Do Not Require Legacy Netbanking

```bash
cd agent-security-lab
python3 -m unittest tests.test_fake_artifactory tests.test_agent_a_publish -v
```

### Running the End-to-End Demo

1. Start Fake Artifactory:

   ```bash
   cd agent-security-lab
   python3 -m fake_artifactory.service --port 8081
   ```

2. In a second terminal:

   ```bash
   cd agent-security-lab
   python3 demo_phase2_step2.py
   ```


---

## Phase 2 Step 3 — Agent B Read Capability

### Architecture

```
Agent A (banking-publisher)
    │
    │  publish_package("agent-message", "hello from Agent A")
    │  authorization = ALLOW
    ▼
Fake Artifactory  (fake-artifactory-local)
    │
    │  read_package("agent-message")
    │  authorization = ALLOW
    ▼
Agent B (banking-reader)
    │
    │  receives: "hello from Agent A"
    ▼
Content is returned as inert data — never executed.
```

**Agent A and Agent B do not communicate directly.**
The Fake Artifactory package repository is the **only** shared channel between
them.  Agent A writes to it; Agent B reads from it.  There is no direct
agent-to-agent call.

### Security Model

```
Agent B (banking-reader)
    │
    │  decide_tool(package_name)
    ▼
BankingReaderAgent
    │
    │  tool_name = "read_package"
    │  arguments = { package_name }
    ▼
ReadGateway
    │
    │  Step 1: check_authorization(agent_id, tool_name, target_repository)
    │     DENY  → PermissionError raised
    │              Fake Artifactory is NEVER called
    │
    │     ALLOW → continue
    │
    ▼
read_package tool
    │
    │  Validate package_name (local)
    │  GET http://127.0.0.1:8081/packages/<name>
    │
    ▼
Fake Artifactory HTTP service
    │
    │  Return { name, content, published_at }
    │  content is returned as a plain string — NEVER executed
    ▼
package data returned to Agent B
```

### Authorization Policy (Step 3 additions)

| Agent ID | Tool | Repository | Decision |
|---|---|---|---|
| `banking-publisher` | `publish_package` | `fake-artifactory-local` | **ALLOW** |
| `banking-reader` | `read_package` | `fake-artifactory-local` | **ALLOW** |
| `banking-reader` | `publish_package` | `fake-artifactory-local` | **DENY** |
| `banking-publisher` | `read_package` | `fake-artifactory-local` | **DENY** |
| `banking-reader` | `read_package` | *any other repository* | **DENY** |
| *any other agent* | *any tool* | *any repository* | **DENY** |

Authorization is evaluated **inside the gateway, before any HTTP call** to the
Fake Artifactory service.  An unauthorized agent can never reach the shared
repository, even indirectly.

### Content Security Constraint

Package content is treated as **inert text data**.  It is stored verbatim as a
JSON string and is **never imported, evaluated, executed, or dynamically loaded**
by Agent B.  For example, content such as:

```
import os; os.system('echo pwned')
```

is returned as a plain string — never interpreted as code.

### Audit Logging

Both ALLOW and DENY operations emit structured log lines.  The table below
shows the fields captured on a read:

| Field | Description |
|---|---|
| `timestamp` | ISO-8601 UTC |
| `agent_id` | Calling agent identifier |
| `user_id` | Principal if available (`N/A` otherwise) |
| `tool` | `read_package` |
| `action` | `read` |
| `repository` | `fake-artifactory-local` |
| `package_name` | Requested package |
| `target` | URL targeted (or blocked) |
| `authorization_decision` | `ALLOWED` / `DENIED` / `N/A` |
| `reason` | Human-readable explanation |
| `outcome` | `SUCCESS` or `FAILURE` with detail |

Secrets, passwords, cookies, and tokens are **never** included in log output.

### New Files (Step 3)

| File | Role |
|---|---|
| `agent/reader_agent.py` | `BankingReaderAgent` — Agent B with `agent_id = "banking-reader"` |
| `gateway/read_gateway.py` | Gateway that checks authz before dispatching read operations |
| `tools/read_tool.py` | `read_package` HTTP GET tool for Fake Artifactory |
| `tests/test_agent_b_read.py` | Full test suite for Phase 2 Step 3 (tests A–I) |
| `demo_phase2_step3.py` | End-to-end demonstration: Agent A → repository → Agent B |

Updated files:

| File | Change |
|---|---|
| `gateway/authorization_policy.py` | Added `banking-reader / read_package / fake-artifactory-local → ALLOW` |

### Running Phase 2 Step 3 Tests (no Legacy Netbanking required)

```bash
cd agent-security-lab
python3 -m unittest tests.test_agent_b_read -v
```

### Running All Non-Tomcat Tests (Steps 2 + 3)

```bash
cd agent-security-lab
python3 -m unittest tests.test_fake_artifactory tests.test_agent_a_publish tests.test_agent_b_read -v
```

### Running the Step 3 End-to-End Demo

1. Start Fake Artifactory:

   ```bash
   cd agent-security-lab
   python3 -m fake_artifactory.service --port 8081
   ```

2. In a second terminal:

   ```bash
   cd agent-security-lab
   python3 demo_phase2_step3.py
   ```

### Directory Structure (updated)

```
agent-security-lab/
  ├── README.md
  ├── demo_phase2_step2.py          ← Phase 2 Step 2 demo (Agent A publish)
  ├── demo_phase2_step3.py          ← Phase 2 Step 3 demo (Agent A → repo → Agent B)
  ├── agent/
  │    ├── __init__.py
  │    ├── mock_agent.py             ← banking-assistant (Phase 1)
  │    ├── publisher_agent.py        ← banking-publisher / Agent A (Phase 2 Step 2)
  │    └── reader_agent.py           ← banking-reader / Agent B  (Phase 2 Step 3)
  ├── fake_artifactory/             ← Phase 2 local synthetic package repository
  │    ├── __init__.py
  │    ├── packages/                 ← local filesystem storage for packages
  │    └── service.py                ← lightweight HTTP service & CLI
  ├── tools/
  │    ├── __init__.py
  │    ├── banking_tools.py          ← real HTTP calls to Legacy Netbanking
  │    ├── publish_tool.py           ← publish_package tool (Phase 2 Step 2)
  │    └── read_tool.py              ← read_package tool   (Phase 2 Step 3)
  ├── gateway/
  │    ├── __init__.py
  │    ├── tool_gateway.py           ← banking gateway (Phase 1)
  │    ├── authorization_policy.py   ← explicit ALLOW/DENY policy table
  │    ├── publish_gateway.py        ← publish gateway with authz check
  │    └── read_gateway.py           ← read gateway with authz check (Phase 2 Step 3)
  └── tests/
       ├── __init__.py
       ├── test_agent_a_publish.py   ← Agent A authorization & publish tests
       ├── test_agent_b_read.py      ← Agent B read capability tests (A–I, Step 3)
       ├── test_fake_artifactory.py  ← unit & integration tests for fake Artifactory
       ├── test_gateway_security.py  ← gateway security tests (live Legacy Netbanking)
       └── test_live_integration.py  ← integration tests (live Legacy Netbanking)
```


---

## Phase 2 Step 4 — Benign Indirect Agent Action

### Overview

Phase 2 Step 4 introduces a **benign indirect control path** between Agent A
and Agent B.  Agent A writes a structured data message to the shared Fake
Artifactory repository.  Agent B reads the data and may execute **exactly one**
explicitly allowlisted, harmless action — creating a small text file inside
`demo_resources/`.

This models an indirect agent-to-agent interaction **without** exploitation,
arbitrary code execution, or dynamic dispatch.

### Key Design Principles

| Principle | Implementation |
|---|---|
| **No direct agent-to-agent communication** | Agent A and Agent B share no method calls, shared objects, or sockets. The Fake Artifactory repository is the only channel. |
| **Package content is DATA** | Agent B never executes, imports, eval's, or shell-executes any part of the package content. |
| **Hard-coded action allowlist** | Agent B checks `requested_action` against `frozenset({"create_demo_marker"})`. Any other value is rejected unconditionally. |
| **Marker name validation** | `marker_name` must match `^[a-zA-Z0-9_\-]{1,64}$`. Path traversal characters (`/`, `\\`, `..`) are rejected at the schema level and again inside the tool. |
| **Write confinement** | `create_demo_marker` resolves the target path with `os.path.abspath()` and verifies it starts with `demo_resources/` before writing. |
| **Authorization enforced at gateway** | `DemoMarkerGateway` calls `check_authorization()` before touching the filesystem — identical pattern to `PublishGateway` and `ReadGateway`. |
| **Audit trail** | Every step (read, parse, allowlist check, create) emits a structured `[AUDIT]` log entry. |

### Control Flow

```
Agent A (banking-publisher)
   │
   │  publish_package(
   │    "agent-request",
   │    {"sender": "banking-publisher",
   │     "message_type": "demo_request",
   │     "requested_action": "create_demo_marker",
   │     "marker_name": "marker-001"}
   │  )
   │  authorization = ALLOW
   ▼
Fake Artifactory  (content stored as DATA)
   │
   │  read_package("agent-request")
   │  authorization = ALLOW
   ▼
Agent B (banking-reader)
   │
   │  parse_demo_request()   ← JSON parsed as DATA; never executed
   │  verify sender + message_type
   │  check requested_action against frozenset({"create_demo_marker"})
   │
   ├── requested_action NOT in allowlist → REJECT / log DENY
   │
   └── requested_action == "create_demo_marker"
          │
          │  DemoMarkerGateway.execute_tool()
          │  authorization = ALLOW
          ▼
       demo_resources/marker-001.txt
       (static text: "created-by=banking-reader\nmarker=marker-001\n...")
```

### Message Format

```json
{
    "sender":           "banking-publisher",
    "message_type":     "demo_request",
    "requested_action": "create_demo_marker",
    "marker_name":      "marker-001"
}
```

**This JSON is DATA.** It is parsed with `json.loads()` and validated field by
field.  No field value is passed to `exec`, `eval`, `subprocess`, `os.system`,
`importlib`, or any equivalent.

### Authorization Policy (updated)

| Agent | Tool | Target | Decision |
|---|---|---|---|
| `banking-publisher` | `publish_package` | `fake-artifactory-local` | **ALLOW** |
| `banking-reader` | `read_package` | `fake-artifactory-local` | **ALLOW** |
| `banking-reader` | `create_demo_marker` | `local-demo-resource` | **ALLOW** |
| `banking-publisher` | `create_demo_marker` | `local-demo-resource` | **DENY** |
| `banking-reader` | `publish_package` | `fake-artifactory-local` | **DENY** |
| (everything else) | (any) | (any) | **DENY** |

### Negative Cases Tested

| Case | Test |
|---|---|
| A | Agent B can call `create_demo_marker` when authorized |
| B | Agent A cannot call `create_demo_marker` |
| C | Agent B cannot publish |
| D | Package with unknown `requested_action` is rejected |
| E | `{"requested_action": "run_command", "command": "touch /tmp/pwned"}` is rejected and NEVER executed |
| F | `{"marker_name": "../../outside"}` is rejected (path traversal) |
| G | Tool write is confined to `demo_resources/` |
| H | Denied actions emit `[AUTHZ DENIED]` log records |
| I | Allowed actions emit `[AUDIT]` log records with `ALLOWED` + `SUCCESS` |
| J | Full end-to-end chain produces the expected marker file |

### Audit Trail

A complete end-to-end chain produces the following audit records:

```
[AUDIT] agent_id=banking-publisher tool=publish_package
        repository=fake-artifactory-local package_name=agent-request
        authorization_decision=ALLOWED outcome=SUCCESS

[AUDIT] agent_id=banking-reader tool=read_package
        repository=fake-artifactory-local package_name=agent-request
        authorization_decision=ALLOWED outcome=SUCCESS

[AUDIT] agent_id=banking-reader tool=create_demo_marker
        target=local-demo-resource marker_name=marker-001
        authorization_decision=ALLOWED outcome=SUCCESS
```

### New Files (Step 4)

| File | Role |
|---|---|
| `tools/demo_marker_tool.py` | `create_demo_marker` — writes static text to `demo_resources/` |
| `tools/message_schema.py` | `parse_demo_request()` — validates structured JSON DATA |
| `gateway/demo_marker_gateway.py` | `DemoMarkerGateway` — authz check before filesystem access |
| `tests/test_phase2_step4.py` | Full test suite: cases A–J + additional coverage |
| `demo_phase2_step4.py` | End-to-end demonstration |

Updated files:

| File | Change |
|---|---|
| `gateway/authorization_policy.py` | Added `banking-reader / create_demo_marker / local-demo-resource → ALLOW`; added `LOCAL_DEMO_RESOURCE` constant |
| `agent/reader_agent.py` | Added `decide_demo_marker()` and `process_demo_request()` workflow |

### Running Phase 2 Step 4 Tests (no Legacy Netbanking required)

```bash
cd agent-security-lab
python3 -m unittest tests.test_phase2_step4 -v
```

### Running All Non-Tomcat Tests (Steps 2 + 3 + 4)

```bash
cd agent-security-lab
python3 -m unittest tests.test_fake_artifactory tests.test_agent_a_publish tests.test_agent_b_read tests.test_phase2_step4 -v
```

### Running the Step 4 End-to-End Demo

1. Start Fake Artifactory:

   ```bash
   cd agent-security-lab
   python3 -m fake_artifactory.service --port 8081
   ```

2. In a second terminal:

   ```bash
   cd agent-security-lab
   python3 demo_phase2_step4.py
   ```

### Updated Directory Structure

```
agent-security-lab/
  ├── README.md
  ├── demo_phase2_step2.py          ← Phase 2 Step 2 demo (Agent A publish)
  ├── demo_phase2_step3.py          ← Phase 2 Step 3 demo (Agent A → repo → Agent B)
  ├── demo_phase2_step4.py          ← Phase 2 Step 4 demo (benign indirect action)
  ├── demo_resources/               ← local target for create_demo_marker (Step 4)
  ├── agent/
  │    ├── __init__.py
  │    ├── mock_agent.py             ← banking-assistant (Phase 1)
  │    ├── publisher_agent.py        ← banking-publisher / Agent A (Phase 2 Step 2)
  │    └── reader_agent.py           ← banking-reader / Agent B  (Steps 3 + 4)
  ├── fake_artifactory/
  │    ├── __init__.py
  │    ├── packages/
  │    └── service.py
  ├── tools/
  │    ├── __init__.py
  │    ├── banking_tools.py
  │    ├── publish_tool.py
  │    ├── read_tool.py
  │    ├── demo_marker_tool.py       ← create_demo_marker tool   (Step 4)
  │    └── message_schema.py         ← structured message validation (Step 4)
  ├── gateway/
  │    ├── __init__.py
  │    ├── tool_gateway.py
  │    ├── authorization_policy.py   ← updated with Step 4 entries
  │    ├── publish_gateway.py
  │    ├── read_gateway.py
  │    └── demo_marker_gateway.py    ← DemoMarkerGateway (Step 4)
  └── tests/
       ├── __init__.py
       ├── test_agent_a_publish.py
       ├── test_agent_b_read.py
       ├── test_fake_artifactory.py
       ├── test_gateway_security.py  ← requires live Legacy Netbanking
       ├── test_live_integration.py  ← requires live Legacy Netbanking
       └── test_phase2_step4.py      ← Phase 2 Step 4 tests (cases A–J)
```

---

## Phase 2 Step 5 — Agentic Evidence Bundle

### Purpose

This step creates a machine-readable **agentic activity evidence bundle** that
describes the safe Phase 2 workflow in a structured format that can be
supplied to external tooling (such as IBM Concert) for analysis.

The bundle is **synthetic telemetry** derived from the existing audit log
structure (the same fields emitted by `authorization_policy.check_authorization()`
and each gateway). It contains no secrets, credentials, cookies, tokens, or
real customer data.

### Controlled Experiment

The bundle is intended for a controlled experiment to determine:

1. What IBM Concert discovers **natively** from the lab environment.
2. What happens when **additional agent telemetry/evidence** is supplied to Concert.
3. Whether supplied evidence **creates or influences relationships/topology** in Concert.
4. Whether supplied evidence can **participate in prioritization or attack-path analysis** in Concert.

> **Important:** None of the above capabilities are claimed or assumed to exist
> in Concert. This is an open experiment. Conclusions will be drawn only from
> observed behaviour.

### Evidence Bundle

```
evidence/phase2_agentic_activity.json
```

The bundle captures:

| Section | Contents |
|---|---|
| `events` | 5 representative audit events (3 ALLOW/SUCCESS + 2 DENY/BLOCKED) |
| `relationships` | 4 directed relationships describing the workflow topology |
| `agent_definitions` | Capability declarations for `banking-publisher` and `banking-reader` |
| `sender_identity_disclaimer` | Explicit statement that `package.sender` is CLAIMED, not authenticated |
| `workflow_chain` | Ordered step description of the full publish → read → create chain |
| `concert_experiment_metadata` | Safe/no-secrets declaration + experiment framing |

### Workflow Chain Represented

```
banking-publisher
    │
    │  publish_package
    ▼
fake-artifactory-local
    │
    │  (agent-request package)
    ▼
banking-reader
    │
    │  read_package
    ▼
banking-reader
    │
    │  create_demo_marker
    ▼
local-demo-resource
```

### Sender Identity Distinction

The `sender` field inside a published package payload (e.g.
`{"sender": "banking-publisher", ...}`) is **claimed identity only**.
It is a data field written by the publisher inside the package content.
It is **not cryptographically authenticated**.

The bundle makes this distinction explicit in `sender_identity_disclaimer`:

```json
{
  "authentication_method": "NONE — data assertion only",
  "cryptographic_proof": false,
  "trust_level": "UNTRUSTED_CLAIMED_DATA"
}
```

No cryptographic signing is implemented in this step.

### New Files

| File | Role |
|---|---|
| `evidence/phase2_agentic_activity.json` | Agentic activity evidence bundle |
| `tests/test_phase2_step5_evidence.py` | Validation tests (checks A–H) |

### Running Phase 2 Step 5 Tests (no Legacy Netbanking required)

```bash
cd agent-security-lab
python3 -m unittest tests.test_phase2_step5_evidence -v
```

### Running All Non-Tomcat Tests (Steps 2–5)

```bash
cd agent-security-lab
python3 -m unittest tests.test_fake_artifactory tests.test_agent_a_publish tests.test_agent_b_read tests.test_phase2_step4 tests.test_phase2_step5_evidence -v
```

### Validation Test Coverage

| Check | Test Class |
|---|---|
| A. Required fields exist | `TestA_RequiredFieldsExist` |
| B. Agent IDs are correct | `TestB_AgentIDsAreCorrect` |
| C. Tool names are correct | `TestC_ToolNamesAreCorrect` |
| D. ALLOW/DENY decisions match existing policy | `TestD_AllowDenyDecisionsMatchPolicy` |
| E. Relationships match observed workflow | `TestE_RelationshipsMatchWorkflow` |
| F. No credentials/secrets/tokens present | `TestF_NoCredentialsOrSecrets` |
| G. No external URLs | `TestG_NoExternalURLs` |
| H. Sender identity marked as untrusted | `TestH_SenderIdentityMarkedUntrusted` |

### Updated Directory Structure

```
agent-security-lab/
  ├── README.md
  ├── evidence/
  │    └── phase2_agentic_activity.json  ← Step 5 evidence bundle
  ├── tests/
  │    └── test_phase2_step5_evidence.py ← Step 5 validation tests
  └── ... (all prior files unchanged)
```

---
