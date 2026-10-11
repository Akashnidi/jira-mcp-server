# Jira Cloud MCP Server

A secure, production-grade Model Context Protocol (MCP) server in Python built with FastMCP (`mcp[cli]`), `httpx`, and `pydantic` to interface with Atlassian Jira Cloud REST API v3.

## Features & Security Guardrails

- **Secret & Credential Handling**:
  - Credentials (`JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `ALLOWED_PROJECTS`) are strictly loaded via environment variables using `python-dotenv`.
  - Credentials and Basic Auth headers are sanitized and masked (`[REDACTED_API_TOKEN]`, `[REDACTED_AUTH]`) across all error messages, logs, and output streams.
- **Strict Input Validation & Injection Prevention**:
  - Pydantic models for all tool parameters.
  - Regex validation for Jira issue keys (`^[A-Z][A-Z0-9]+-[0-9]+$`, e.g. `NOC-123`).
  - Regex validation for project keys (`^[A-Z][A-Z0-9]+$`, e.g. `NOC`).
  - Strict length limits: `summary` (max 255 chars), `description` (max 10,000 chars).
  - Sanitization of summary strings to strip newlines and control characters (`\r`, `\n`).
- **JQL Injection Guardrail**:
  - Automatic query scoping within permitted project boundaries: `(project IN ("NOC")) AND ({user_jql})`.
  - Validates balanced parentheses and quotation marks.
  - Rejects SQL/JQL comments (`/*`, `*/`, `--`), statement separators (`;`), and negative operators (`!=`, `NOT IN`, `IS NOT`).
  - Rejects queries targeting unauthorized projects.
- **Principle of Least Privilege**:
  - Hardcoded project whitelist via `ALLOWED_PROJECTS="NOC"`.
  - Immediate authorization error if any operation attempts to access an unpermitted project.
- **Network Resilience & Timeouts**:
  - `httpx.AsyncClient` with explicit timeouts (`connect: 5.0s`, `read: 10.0s`).
  - Graceful handling of HTTP 429 rate limits (extracting `Retry-After`), HTTP 401, 403, 404, and network drops.
  - Automatic support for Jira Cloud REST API v3 `/rest/api/3/search/jql` with fallback to `/rest/api/3/search`.

---

## Configuration

Create a `.env` file in the root directory (based on `.env.example`):

```bash
# Jira Cloud Base URL
JIRA_BASE_URL=https://your-domain.atlassian.net

# Atlassian Account Email
JIRA_EMAIL=your-email@example.com

# Atlassian API Token
JIRA_API_TOKEN=your_atlassian_api_token_here

# Whitelist of permitted Jira projects (comma-separated)
ALLOWED_PROJECTS=NOC
```

---

## Running the Server

### Direct Execution
```bash
uv run main.py
```

### Via MCP CLI
```bash
uv run mcp run main.py
```

### FastMCP Development Inspector
```bash
uv run mcp dev main.py
```

---

## MCP Client Configuration

### 1. Claude Code

#### Via CLI Command:
Run the following command in your terminal to register the server with Claude Code:

```bash
claude mcp add jira-mcp-server -- uv --directory "D:\mcp\servers\jira-mcp-server" run main.py
```

#### Via Configuration File (`~/.claude.json` or project `.claude.json`):
```json
{
  "mcpServers": {
    "jira-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "D:\\mcp\\servers\\jira-mcp-server",
        "run",
        "main.py"
      ]
    }
  }
}
```

*(Note: On Windows, if `uv` is not on the system PATH for GUI processes, replace `"uv"` with the full executable path, e.g., `"C:\\Users\\<username>\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\uv.exe"` or `"%USERPROFILE%\\.cargo\\bin\\uv.exe"`).*

---

### 2. Claude Desktop

Add the following to your `claude_desktop_config.json`:
- **Windows Path**: `%APPDATA%\Claude\claude_desktop_config.json` (or `%LOCALAPPDATA%\Packages\Claude_...\LocalCache\Roaming\Claude\claude_desktop_config.json`)
- **macOS Path**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "jira-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "D:\\mcp\\servers\\jira-mcp-server",
        "run",
        "main.py"
      ]
    }
  }
}
```

---

## MCP Tools

### 1. `search_issues`
- **Arguments**:
  - `jql` (str, optional): JQL query string.
  - `max_results` (int, default: 50): Number of results to return (1-100).
- **Behavior**: Scopes search to `ALLOWED_PROJECTS` and returns structured JSON with `key`, `summary`, `status`, `assignee`, `reporter`, `created`, and `updated`.

### 2. `get_issue`
- **Arguments**:
  - `issue_key` (str): Jira issue key (e.g. `NOC-123`).
- **Behavior**: Enforces regex and project whitelist. Returns sanitized summary, status, assignee, and plain-text description converted from Atlassian Document Format (ADF).

### 3. `create_issue`
- **Arguments**:
  - `project_key` (str): Target project key (must be in `ALLOWED_PROJECTS`).
  - `summary` (str): Issue title (1-255 characters, control characters stripped).
  - `description` (str, optional): Issue description (max 10,000 characters). Automatically formatted into standard ADF JSON.
  - `issue_type` (str, default: `"Task"`): Issue type name.
- **Behavior**: Creates issue and returns `{"key": issue_key, "id": issue_id, "status": "created"}`.

### 4. `update_issue`
- **Arguments**:
  - `issue_key` (str): Jira issue key to update.
  - `summary` (str, optional): New summary title.
  - `description` (str, optional): New description (converted to ADF).
- **Behavior**: Validates whitelist, requires at least one field to update, and returns confirmation.

### 5. `transition_issue`
- **Arguments**:
  - `issue_key` (str): Jira issue key.
  - `target_status` (str): Target workflow status name (case-insensitive, e.g. `'In Progress'`, `'Done'`).
- **Behavior**: Queries available transitions for the ticket, matches target status, executes transition, and returns confirmation of new status.
