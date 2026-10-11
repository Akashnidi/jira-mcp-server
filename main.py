"""
Model Context Protocol (MCP) server in Python using FastMCP, httpx, and Pydantic
for interfacing securely with the Atlassian Jira Cloud REST API v3.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator

# ------------------------------------------------------------------------------
# FastMCP / MCPServer Import Compatibility (Supports MCP SDK 1.x & 2.x)
# ------------------------------------------------------------------------------
try:
    from mcp.server.mcpserver import MCPServer as FastMCP
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp.exceptions import ToolError
    except ImportError:
        raise ImportError(
            "Neither MCPServer nor FastMCP could be imported. Please install 'mcp[cli]'."
        )

# ------------------------------------------------------------------------------
# Environment & Configuration Loading
# ------------------------------------------------------------------------------
env_file = Path(__file__).resolve().parent / ".env"
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
else:
    load_dotenv()

JIRA_BASE_URL = os.getenv("JIRA_BASE_URL", "").strip().rstrip("/")
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "").strip()
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "").strip()

raw_allowed = os.getenv("ALLOWED_PROJECTS", "").strip()
ALLOWED_PROJECTS: set[str] = {
    p.strip().upper() for p in raw_allowed.split(",") if p.strip()
}

# ------------------------------------------------------------------------------
# Security Validation & Sanitization Constants & Helpers
# ------------------------------------------------------------------------------
ISSUE_KEY_REGEX = re.compile(r"^[A-Z][A-Z0-9]+-[0-9]+$")
PROJECT_KEY_REGEX = re.compile(r"^[A-Z][A-Z0-9]+$")
CONTROL_CHAR_REGEX = re.compile(r"[\r\n\t]+")
DISALLOWED_CHARS_REGEX = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_sensitive_data(text: str) -> str:
    """
    Strips Jira API tokens, Basic Auth headers, and sensitive credentials
    from error messages, outputs, and log texts to prevent credential leakage.
    """
    if not text:
        return ""
    if JIRA_API_TOKEN and JIRA_API_TOKEN in text:
        text = text.replace(JIRA_API_TOKEN, "[REDACTED_API_TOKEN]")
    text = re.sub(
        r"Basic\s+[A-Za-z0-9+/=]+", "Basic [REDACTED_AUTH]", text, flags=re.IGNORECASE
    )
    text = re.sub(
        r"['\"]Authorization['\"]\s*:\s*['\"][^'\"]+['\"]",
        "'Authorization': '[REDACTED]'",
        text,
        flags=re.IGNORECASE,
    )
    return text


def verify_project_allowed(project_key: str) -> str:
    """
    Verifies that the project_key is permitted under ALLOWED_PROJECTS.
    Rejects unauthorized access immediately with an explicit authorization error.
    """
    key = project_key.strip()
    if not PROJECT_KEY_REGEX.match(key):
        raise ToolError(
            f"Invalid project key format: '{project_key}'. Must match pattern '^[A-Z][A-Z0-9]+$' (e.g., 'NOC')."
        )
    if not ALLOWED_PROJECTS:
        raise ToolError(
            "Authorization error: ALLOWED_PROJECTS configuration is empty. Access denied."
        )
    if key not in ALLOWED_PROJECTS:
        allowed_list = sorted(list(ALLOWED_PROJECTS))
        raise ToolError(
            f"Authorization error: Project '{key}' is not in ALLOWED_PROJECTS whitelist: {allowed_list}"
        )
    return key


def verify_issue_key_allowed(issue_key: str) -> str:
    """
    Validates issue key format (e.g., 'NOC-123') and ensures its project prefix is allowed.
    """
    key = issue_key.strip()
    if not ISSUE_KEY_REGEX.match(key):
        raise ToolError(
            f"Invalid issue key format: '{issue_key}'. Must match pattern '^[A-Z][A-Z0-9]+-[0-9]+$' (e.g., 'NOC-123')."
        )
    project_prefix = key.split("-")[0]
    verify_project_allowed(project_prefix)
    return key


def validate_and_scope_jql(jql: str, allowed_projects: set[str]) -> str:
    """
    JQL Injection Guardrail:
    - Restricts queries to project boundaries.
    - Prevents arbitrary wildcard execution or comment/script injection.
    - Enforces allowed project scope explicitly at the database query level.
    """
    if not allowed_projects:
        raise ToolError(
            "Authorization error: ALLOWED_PROJECTS configuration is empty. Access denied."
        )

    proj_list = ", ".join(f'"{p}"' for p in sorted(allowed_projects))
    cleaned = (jql or "").strip()

    if not cleaned:
        return f"project IN ({proj_list})"

    if len(cleaned) > 2000:
        raise ToolError("JQL query exceeds maximum allowed length of 2,000 characters.")

    # Check for unbalanced quotes
    if cleaned.count('"') % 2 != 0 or cleaned.count("'") % 2 != 0:
        raise ToolError("Invalid JQL syntax: Unbalanced quotation marks.")

    # Check for balanced parentheses
    depth = 0
    for ch in cleaned:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth < 0:
            raise ToolError("Invalid JQL syntax: Unbalanced parentheses.")
    if depth != 0:
        raise ToolError("Invalid JQL syntax: Unbalanced parentheses.")

    # Prevent SQL/JQL comment injection or statement separators
    if re.search(r"(;|/\*|\*/|--|\x00)", cleaned):
        raise ToolError(
            "JQL security guardrail triggered: Disallowed characters or comment syntax detected."
        )

    # Disallow negative project operators (e.g., project !=, project NOT IN, project IS NOT)
    if re.search(r"\bproject\s*(!=|not\s+in\b|is\s+not\b)", cleaned, re.IGNORECASE):
        raise ToolError(
            "JQL security guardrail triggered: Negative project operators (!=, NOT IN, IS NOT) are forbidden."
        )

    # Inspect all project references in JQL to ensure no unauthorized project is queried
    matches = re.finditer(
        r"\bproject\s*(?:=|in)\s*(\([^\)]+\)|(?:\"[^\"]+\")|(?:\'[^\']+\')|[A-Za-z0-9_-]+)",
        cleaned,
        re.IGNORECASE,
    )
    for m in matches:
        val = m.group(1).strip()
        if val.startswith("(") and val.endswith(")"):
            keys = [
                k.strip().strip("\"'").upper()
                for k in val[1:-1].split(",")
                if k.strip()
            ]
        else:
            keys = [val.strip("\"'").upper()]
        for k in keys:
            if k not in allowed_projects:
                allowed_list = sorted(list(allowed_projects))
                raise ToolError(
                    f"Authorization error: JQL references project '{k}', which is not in ALLOWED_PROJECTS: {allowed_list}"
                )

    # Explicitly enforce project boundary
    return f"(project IN ({proj_list})) AND ({cleaned})"


# ------------------------------------------------------------------------------
# Atlassian Document Format (ADF) Helpers
# ------------------------------------------------------------------------------
def text_to_adf(text: str) -> dict[str, Any]:
    """
    Constructs standard Atlassian Document Format (ADF) JSON structure for text.
    """
    if not text:
        return {"type": "doc", "version": 1, "content": []}

    paragraphs = text.split("\n\n")
    content_blocks = []
    for para in paragraphs:
        lines = para.split("\n")
        para_content = []
        for i, line in enumerate(lines):
            cleaned_line = line.strip()
            if cleaned_line:
                para_content.append({"type": "text", "text": cleaned_line})
            if i < len(lines) - 1:
                para_content.append({"type": "hardBreak"})
        if para_content:
            content_blocks.append({"type": "paragraph", "content": para_content})

    if not content_blocks:
        content_blocks = [{"type": "paragraph", "content": []}]

    return {"type": "doc", "version": 1, "content": content_blocks}


def adf_to_text(adf_data: Any) -> str:
    """
    Extracts readable plain text from Atlassian Document Format (ADF) data structure.
    """
    if not adf_data:
        return ""
    if isinstance(adf_data, str):
        return adf_data
    if not isinstance(adf_data, dict):
        return str(adf_data)

    pieces: list[str] = []

    def extract(node: Any):
        if not isinstance(node, dict):
            return
        node_type = node.get("type")
        if node_type == "text":
            pieces.append(node.get("text", ""))
        elif node_type == "hardBreak":
            pieces.append("\n")

        for child in node.get("content", []):
            extract(child)

        if node_type in ("paragraph", "heading", "listItem"):
            pieces.append("\n")

    extract(adf_data)
    result = re.sub(r"\n{3,}", "\n\n", "".join(pieces)).strip()
    return result


# ------------------------------------------------------------------------------
# Pydantic Input Validation Models
# ------------------------------------------------------------------------------
class SearchIssuesInput(BaseModel):
    jql: str = Field(
        default="",
        max_length=2000,
        description="JQL query string to search issues (e.g., 'status = \"To Do\"')",
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum number of issues to return (1-100)",
    )


class GetIssueInput(BaseModel):
    issue_key: str = Field(
        ...,
        description="Jira issue key (e.g., 'NOC-123')",
    )

    @field_validator("issue_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        return verify_issue_key_allowed(v)


class CreateIssueInput(BaseModel):
    project_key: str = Field(
        ...,
        description="Project key (e.g., 'NOC')",
    )
    summary: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Brief summary / title of the issue (max 255 chars)",
    )
    description: str = Field(
        default="",
        max_length=10000,
        description="Detailed description of the issue (max 10,000 chars)",
    )
    issue_type: str = Field(
        default="Task",
        min_length=1,
        max_length=50,
        description="Issue type (e.g., 'Task', 'Bug', 'Incident')",
    )

    @field_validator("project_key")
    @classmethod
    def validate_project(cls, v: str) -> str:
        clean = v.strip()
        if not PROJECT_KEY_REGEX.match(clean):
            raise ToolError(
                f"Invalid project key format: '{v}'. Must match pattern '^[A-Z][A-Z0-9]+$' (e.g., 'NOC')."
            )
        verify_project_allowed(clean)
        return clean

    @field_validator("summary")
    @classmethod
    def sanitize_summary(cls, v: str) -> str:
        sanitized = CONTROL_CHAR_REGEX.sub(" ", v).strip()
        sanitized = DISALLOWED_CHARS_REGEX.sub("", sanitized)
        if not sanitized:
            raise ToolError("Summary cannot be empty after stripping control characters.")
        if len(sanitized) > 255:
            raise ToolError("Summary exceeds maximum allowable length of 255 characters.")
        return sanitized

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        if len(v) > 10000:
            raise ToolError("Description exceeds maximum allowable length of 10,000 characters.")
        return v


class UpdateIssueInput(BaseModel):
    issue_key: str = Field(
        ...,
        description="Jira issue key to update (e.g., 'NOC-123')",
    )
    summary: Optional[str] = Field(
        default=None,
        max_length=255,
        description="New summary title (max 255 chars)",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=10000,
        description="New description (max 10,000 chars)",
    )

    @field_validator("issue_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        return verify_issue_key_allowed(v)

    @field_validator("summary")
    @classmethod
    def sanitize_summary(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        sanitized = CONTROL_CHAR_REGEX.sub(" ", v).strip()
        sanitized = DISALLOWED_CHARS_REGEX.sub("", sanitized)
        if not sanitized:
            raise ToolError("Summary cannot be empty after stripping control characters.")
        if len(sanitized) > 255:
            raise ToolError("Summary exceeds maximum allowable length of 255 characters.")
        return sanitized

    @model_validator(mode="after")
    def check_at_least_one_field(self) -> "UpdateIssueInput":
        if self.summary is None and self.description is None:
            raise ToolError("At least one of 'summary' or 'description' must be provided for update.")
        return self


class TransitionIssueInput(BaseModel):
    issue_key: str = Field(
        ...,
        description="Jira issue key (e.g., 'NOC-123')",
    )
    target_status: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Target status name to transition to (case-insensitive, e.g., 'In Progress', 'Done')",
    )

    @field_validator("issue_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        return verify_issue_key_allowed(v)

    @field_validator("target_status")
    @classmethod
    def sanitize_target_status(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ToolError("Target status cannot be empty.")
        return clean


# ------------------------------------------------------------------------------
# Jira Async HTTP Client with Timeouts & Resilient Error Handling
# ------------------------------------------------------------------------------
class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str):
        if not base_url or not email or not api_token:
            raise ValueError(
                "Jira configuration missing. JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN must be set."
            )
        self.base_url = base_url.rstrip("/")
        self.auth = (email, api_token)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # Explicit timeouts: connect: 5.0s, read: 10.0s
        self.timeout = httpx.Timeout(15.0, connect=5.0, read=10.0, write=10.0)

    def _handle_error_response(self, resp: httpx.Response, action_description: str) -> None:
        status = resp.status_code
        if status == 401:
            raise ToolError(
                "Authentication failed (HTTP 401): Jira credentials rejected. "
                "Verify JIRA_EMAIL and JIRA_API_TOKEN in your environment."
            )
        elif status == 403:
            raise ToolError(
                f"Access forbidden (HTTP 403): User lacks permission to {action_description}."
            )
        elif status == 404:
            raise ToolError(
                f"Resource not found (HTTP 404): The requested item for {action_description} was not found."
            )
        elif status == 429:
            retry_after = resp.headers.get("Retry-After", "unknown")
            raise ToolError(
                f"Rate limit exceeded (HTTP 429): Jira request throttled. Retry after {retry_after} seconds."
            )
        else:
            try:
                err_json = resp.json()
                messages = err_json.get("errorMessages", [])
                field_errors = err_json.get("errors", {})
                parts = []
                if messages:
                    parts.extend(messages)
                if field_errors:
                    parts.append(str(field_errors))
                detail = "; ".join(parts) if parts else resp.text[:300]
            except Exception:
                detail = resp.text[:300]
            clean_detail = sanitize_sensitive_data(detail)
            raise ToolError(f"Jira API error (HTTP {status}) while {action_description}: {clean_detail}")

    async def get(self, path: str, params: Optional[dict[str, Any]] = None, action_desc: str = "fetching resource") -> httpx.Response:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(auth=self.auth, headers=self.headers, timeout=self.timeout) as client:
                resp = await client.get(url, params=params)
                if resp.is_error:
                    self._handle_error_response(resp, action_desc)
                return resp
        except (httpx.ConnectTimeout, httpx.ConnectError):
            raise ToolError(
                "Network error: Unable to connect to Jira within 5.0 seconds. Check JIRA_BASE_URL and network."
            )
        except httpx.ReadTimeout:
            raise ToolError("Network error: Jira operation timed out after 10.0 seconds.")
        except httpx.RequestError as e:
            raise ToolError(f"Network error communicating with Jira: {sanitize_sensitive_data(str(e))}")

    async def post(self, path: str, json_data: dict[str, Any], action_desc: str = "creating resource") -> httpx.Response:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(auth=self.auth, headers=self.headers, timeout=self.timeout) as client:
                resp = await client.post(url, json=json_data)
                if resp.is_error:
                    self._handle_error_response(resp, action_desc)
                return resp
        except (httpx.ConnectTimeout, httpx.ConnectError):
            raise ToolError(
                "Network error: Unable to connect to Jira within 5.0 seconds. Check JIRA_BASE_URL and network."
            )
        except httpx.ReadTimeout:
            raise ToolError("Network error: Jira operation timed out after 10.0 seconds.")
        except httpx.RequestError as e:
            raise ToolError(f"Network error communicating with Jira: {sanitize_sensitive_data(str(e))}")

    async def put(self, path: str, json_data: dict[str, Any], action_desc: str = "updating resource") -> httpx.Response:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(auth=self.auth, headers=self.headers, timeout=self.timeout) as client:
                resp = await client.put(url, json=json_data)
                if resp.is_error:
                    self._handle_error_response(resp, action_desc)
                return resp
        except (httpx.ConnectTimeout, httpx.ConnectError):
            raise ToolError(
                "Network error: Unable to connect to Jira within 5.0 seconds. Check JIRA_BASE_URL and network."
            )
        except httpx.ReadTimeout:
            raise ToolError("Network error: Jira operation timed out after 10.0 seconds.")
        except httpx.RequestError as e:
            raise ToolError(f"Network error communicating with Jira: {sanitize_sensitive_data(str(e))}")


# Initialize Jira client helper (lazy verification on tool calls)
def get_jira_client() -> JiraClient:
    if not JIRA_BASE_URL or not JIRA_EMAIL or not JIRA_API_TOKEN:
        raise ToolError(
            "Configuration error: JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN must be configured in environment."
        )
    return JiraClient(
        base_url=JIRA_BASE_URL,
        email=JIRA_EMAIL,
        api_token=JIRA_API_TOKEN,
    )


# ------------------------------------------------------------------------------
# FastMCP Server Instance
# ------------------------------------------------------------------------------
mcp = FastMCP("jira-server")
app = mcp
server = mcp


# ------------------------------------------------------------------------------
# Tool 1: search_issues
# ------------------------------------------------------------------------------
@mcp.tool()
async def search_issues(
    jql: str = Field(
        default="",
        max_length=2000,
        description="JQL query string (e.g. 'status = \"To Do\"')",
    ),
    max_results: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum number of issues to return (1-100)",
    ),
) -> dict[str, Any]:
    """
    Search for Jira issues using JQL restricted strictly to ALLOWED_PROJECTS.
    Extracts key, summary, status, assignee, reporter, created, and updated timestamps.
    """
    params = SearchIssuesInput(jql=jql, max_results=max_results)
    scoped_jql = validate_and_scope_jql(params.jql, ALLOWED_PROJECTS)
    client = get_jira_client()

    fields_to_fetch = [
        "summary",
        "status",
        "assignee",
        "reporter",
        "created",
        "updated",
    ]

    payload = {
        "jql": scoped_jql,
        "maxResults": params.max_results,
        "fields": fields_to_fetch,
    }

    # Jira Cloud REST API v3 supports /rest/api/3/search/jql
    # Fallback to /rest/api/3/search for older instances
    try:
        resp = await client.post(
            "/rest/api/3/search/jql",
            json_data=payload,
            action_desc=f"searching issues with JQL '{scoped_jql}'",
        )
    except ToolError as e:
        if "HTTP 404" in str(e) or "HTTP 410" in str(e):
            resp = await client.post(
                "/rest/api/3/search",
                json_data=payload,
                action_desc=f"searching issues with JQL '{scoped_jql}'",
            )
        else:
            raise

    data = resp.json()
    raw_issues = data.get("issues", [])
    results: list[dict[str, Any]] = []

    for issue in raw_issues:
        fields = issue.get("fields", {}) or {}
        status_obj = fields.get("status") or {}
        assignee_obj = fields.get("assignee") or {}
        reporter_obj = fields.get("reporter") or {}

        results.append(
            {
                "key": issue.get("key"),
                "summary": fields.get("summary", ""),
                "status": status_obj.get("name"),
                "assignee": assignee_obj.get("displayName"),
                "reporter": reporter_obj.get("displayName"),
                "created": fields.get("created"),
                "updated": fields.get("updated"),
            }
        )

    return {
        "total": len(results),
        "issues": results,
    }


# ------------------------------------------------------------------------------
# Tool 2: get_issue
# ------------------------------------------------------------------------------
@mcp.tool()
async def get_issue(
    issue_key: str = Field(
        ...,
        description="Jira issue key (e.g. 'NOC-123')",
    ),
) -> dict[str, Any]:
    """
    Retrieve details of a Jira issue by key.
    Enforces format validation and whitelist checks against ALLOWED_PROJECTS.
    Returns sanitized summary, plain-text description (extracted from ADF), status, and assignee.
    """
    params = GetIssueInput(issue_key=issue_key)
    client = get_jira_client()

    resp = await client.get(
        f"/rest/api/3/issue/{params.issue_key}",
        params={"fields": "summary,description,status,assignee,reporter,created,updated"},
        action_desc=f"retrieving issue '{params.issue_key}'",
    )

    data = resp.json()
    fields = data.get("fields", {}) or {}
    status_obj = fields.get("status") or {}
    assignee_obj = fields.get("assignee") or {}
    reporter_obj = fields.get("reporter") or {}

    raw_description = fields.get("description")
    description_text = adf_to_text(raw_description)

    return {
        "key": data.get("key", params.issue_key),
        "summary": fields.get("summary", ""),
        "description": description_text,
        "status": status_obj.get("name"),
        "assignee": assignee_obj.get("displayName"),
        "reporter": reporter_obj.get("displayName"),
        "created": fields.get("created"),
        "updated": fields.get("updated"),
    }


# ------------------------------------------------------------------------------
# Tool 3: create_issue
# ------------------------------------------------------------------------------
@mcp.tool()
async def create_issue(
    project_key: str = Field(
        ...,
        description="Project key matching ALLOWED_PROJECTS (e.g. 'NOC')",
    ),
    summary: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Summary title of the issue (max 255 characters)",
    ),
    description: str = Field(
        default="",
        max_length=10000,
        description="Detailed description (max 10,000 characters)",
    ),
    issue_type: str = Field(
        default="Task",
        min_length=1,
        max_length=50,
        description="Issue type name (e.g. 'Task', 'Bug', 'Incident')",
    ),
) -> dict[str, Any]:
    """
    Create a new Jira issue within an allowed project.
    Validates input limits, sanitizes control characters, and constructs ADF for the description.
    Returns {"key": issue_key, "id": issue_id, "status": "created"}.
    """
    params = CreateIssueInput(
        project_key=project_key,
        summary=summary,
        description=description,
        issue_type=issue_type,
    )
    client = get_jira_client()

    adf_description = text_to_adf(params.description)
    payload = {
        "fields": {
            "project": {"key": params.project_key},
            "summary": params.summary,
            "description": adf_description,
            "issuetype": {"name": params.issue_type},
        }
    }

    resp = await client.post(
        "/rest/api/3/issue",
        json_data=payload,
        action_desc=f"creating issue in project '{params.project_key}'",
    )

    data = resp.json()
    return {
        "key": data.get("key"),
        "id": data.get("id"),
        "status": "created",
    }


# ------------------------------------------------------------------------------
# Tool 4: update_issue
# ------------------------------------------------------------------------------
@mcp.tool()
async def update_issue(
    issue_key: str = Field(
        ...,
        description="Jira issue key to update (e.g. 'NOC-123')",
    ),
    summary: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional new summary title",
    ),
    description: Optional[str] = Field(
        default=None,
        max_length=10000,
        description="Optional new description",
    ),
) -> dict[str, Any]:
    """
    Update summary and/or description of an existing Jira issue.
    Enforces project whitelist, validates lengths, and converts description to ADF.
    Returns a confirmation message.
    """
    params = UpdateIssueInput(
        issue_key=issue_key,
        summary=summary,
        description=description,
    )
    client = get_jira_client()

    fields_update: dict[str, Any] = {}
    if params.summary is not None:
        fields_update["summary"] = params.summary
    if params.description is not None:
        fields_update["description"] = text_to_adf(params.description)

    payload = {"fields": fields_update}

    await client.put(
        f"/rest/api/3/issue/{params.issue_key}",
        json_data=payload,
        action_desc=f"updating issue '{params.issue_key}'",
    )

    return {
        "status": "success",
        "key": params.issue_key,
        "message": f"Issue '{params.issue_key}' successfully updated.",
    }


# ------------------------------------------------------------------------------
# Tool 5: transition_issue
# ------------------------------------------------------------------------------
@mcp.tool()
async def transition_issue(
    issue_key: str = Field(
        ...,
        description="Jira issue key (e.g. 'NOC-123')",
    ),
    target_status: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Target status name (case-insensitive, e.g. 'In Progress', 'Done', 'Resolved')",
    ),
) -> dict[str, Any]:
    """
    Transition a Jira issue to a new status.
    Fetches available transitions, performs case-insensitive matching, and executes the transition.
    Returns a confirmation of the new status.
    """
    params = TransitionIssueInput(
        issue_key=issue_key,
        target_status=target_status,
    )
    client = get_jira_client()

    # 1. Fetch available transitions
    resp = await client.get(
        f"/rest/api/3/issue/{params.issue_key}/transitions",
        action_desc=f"retrieving transitions for issue '{params.issue_key}'",
    )

    data = resp.json()
    transitions = data.get("transitions", [])

    matched_transition: Optional[dict[str, Any]] = None
    target_lower = params.target_status.lower()

    for t in transitions:
        name = t.get("name", "").strip().lower()
        to_name = (t.get("to") or {}).get("name", "").strip().lower()
        if name == target_lower or to_name == target_lower:
            matched_transition = t
            break

    if not matched_transition:
        available_names = [
            f"'{t.get('name')}'" for t in transitions if t.get("name")
        ]
        available_str = ", ".join(available_names) if available_names else "none"
        raise ToolError(
            f"Cannot transition issue '{params.issue_key}' to '{params.target_status}'. "
            f"Available transitions for this issue: [{available_str}]."
        )

    transition_id = matched_transition.get("id")
    actual_name = matched_transition.get("name")

    # 2. Execute transition
    payload = {"transition": {"id": transition_id}}
    await client.post(
        f"/rest/api/3/issue/{params.issue_key}/transitions",
        json_data=payload,
        action_desc=f"transitioning issue '{params.issue_key}' to '{actual_name}'",
    )

    return {
        "status": "success",
        "key": params.issue_key,
        "new_status": actual_name,
        "transition_id": transition_id,
        "message": f"Issue '{params.issue_key}' successfully transitioned to '{actual_name}'.",
    }


# ------------------------------------------------------------------------------
# Server Entry Point
# ------------------------------------------------------------------------------
def main():
    """Main execution function to run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
