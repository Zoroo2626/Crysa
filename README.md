# Crysa

**AI-native security reasoning engine for coding agents.**

Crysa is not a linter. It is not a pattern matcher. It is not a SAST tool.
It is a security reasoning layer that uses an LLM to think like a bug bounty
hunter and catch logic-level vulnerabilities that no regex or AST rule can find.

---

## The Problem

AI coding agents ship code fast. They also ship insecure code fast.

- IDORs where the agent forgot to check ownership
- Auth bypasses because the middleware was "assumed"
- Mass assignment because the model binds directly to request data
- Business logic flaws that no static analyzer understands

Traditional SAST tools catch typos. Crysa catches the vulnerabilities that
require **understanding what the code is supposed to do** — and what an
attacker can make it do instead.

## What Crysa Does Differently

| Traditional SAST | Crysa |
|---|---|
| Regex pattern matching | LLM reasoning about code intent |
| Catches syntax issues | Catches logic-level vulnerabilities |
| Thousands of false positives | Precise, contextual findings |
| Needs rule updates for new patterns | Understands novel attack vectors |
| "This looks suspicious" | "Any authenticated user can update any order" |

Crysa sends your code to an LLM configured to think like a senior application
security researcher. Before reviewing any file, it builds a **security context
snapshot** of your codebase — understanding your framework, auth middleware,
routes, data models, and role definitions — so it can reason accurately about
authorization, data flow, and attacker-reachable code paths.

---

## Installation

```bash
pip install crysa
crysa init
```

No Docker, no database, no cloud service. Works with any OpenAI-compatible API.

### From source

```bash
git clone https://github.com/crysa/crysa
cd crysa
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# 1. Configure (writes .env and config.yaml)
crysa init

# 2. Scan a directory
crysa scan ./src

# 3. Or scan a single file
crysa scan ./api/views.py
```

---

## CLI Reference

### Global Flags

These flags apply to every command and must be placed **before** the subcommand:

```bash
crysa --verbose scan ./src      # Show debug output (context building, LLM calls, timing)
crysa --quiet   scan ./src      # Suppress everything except findings
crysa --exit-code scan ./src    # Exit with code 1 if any findings are reported (CI-friendly)
crysa -V scan ./src             # Short form of --verbose
crysa -q scan ./src             # Short form of --quiet
```

You can also set verbosity via environment variables:

```bash
CRYSA_VERBOSE=1 crysa scan ./src
CRYSA_QUIET=1  crysa scan ./src
```

> **`--exit-code`** is the flag to use in any script or CI step that needs to
> fail the build when findings are found. Without it, Crysa always exits 0.

---

### `crysa scan`

Scan a file or directory for security vulnerabilities.

```bash
crysa scan PATH [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--severity` | `-s` | `LOW` | Minimum severity to report: `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` |
| `--format` | `-f` | `rich` | Output format: `rich\|json\|sarif` |
| `--fix` | | off | Show fix suggestions inline with each finding |
| `--watch` | | off | Keep running and re-scan on every file change |
| `--vuln-class` | `-v` | all | Comma-separated vulnerability classes to focus on |
| `--workers` | `-w` | `4` | Concurrent LLM threads for directory scans |
| `--output` | `-o` | | Write results to a file (format inferred from extension: `.json`, `.sarif`) |
| `--baseline` | `-b` | | Baseline JSON file — suppress known findings, only report new ones |

#### Examples

```bash
# Scan with sensible defaults (all severities, rich output)
crysa scan ./src

# Only report HIGH and CRITICAL findings
crysa scan ./src --severity HIGH

# JSON output for CI pipelines — goes to stdout, safe to pipe or redirect
crysa scan ./src --format json
crysa scan ./src --format json > report.json

# Write results to a file (format inferred from extension)
crysa scan ./src --output report.json
crysa scan ./src --output report.sarif

# SARIF output for GitHub Code Scanning
crysa scan ./src --format sarif > results.sarif

# Fail CI if any findings exist
crysa --exit-code scan ./src --severity HIGH

# Show fix suggestions alongside each finding
crysa scan ./src --fix

# Focus on a specific vulnerability class
crysa scan ./src --vuln-class IDOR,AUTH_BYPASS

# Scan faster on a large codebase (more concurrent LLM calls)
crysa scan ./src --workers 8

# Watch mode — re-scan on every save
crysa scan ./src --watch

# Baseline workflow: save today's findings, then only see NEW ones tomorrow
crysa scan ./src --format json --output baseline.json
crysa scan ./src --baseline baseline.json
```

#### Progress Bar and Streaming Output

When scanning a directory in `rich` format, Crysa shows:

1. A live progress bar with the current file name, completion percentage, and elapsed time
2. Findings **stream to the terminal as each file finishes** — you see results immediately,
   not after the entire scan completes

```
  crysa/engine/reviewer.py ━━━━━━━━━━━━━━━━━━━━━━ 12/24  0:00:08

  CRITICAL  •  IDOR  •  HIGH CONFIDENCE
  api/views/orders.py  lines 42-58
  ┌─ CRYSA-A3F2B1 ──────────────────────────────────────────────────────┐
  │  Missing ownership check on order update endpoint                    │
  │  ...                                                                 │
  └──────────────────────────────────────────────────────────────────────┘
```

Files are scanned concurrently (controlled by `--workers`), so the order
findings appear may differ from file order on disk.

---

### `crysa watch`

Watch a directory and automatically scan any file the moment it changes.
Designed to run alongside an AI coding agent in a split terminal.

```bash
crysa watch PATH [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--severity` | `-s` | `LOW` | Minimum severity to report |
| `--format` | `-f` | `rich` | Output format |

```bash
# Watch in background while your agent writes code
crysa watch ./src
```

---

### `crysa diff`

Scan a git diff for security vulnerabilities introduced by recent changes.

```bash
# Pipe a diff from stdin
git diff HEAD | crysa diff

# Scan staged changes (before committing)
crysa diff --staged

# Output as SARIF
git diff HEAD | crysa diff --format sarif
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--staged` | | off | Scan staged (`git add`'d) changes |
| `--format` | `-f` | `rich` | Output format: `rich\|json\|sarif` |

---

### `crysa mcp`

Start the Crysa MCP server for integration with AI coding agents.

```bash
crysa mcp
crysa mcp --port 3333 --host 127.0.0.1
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--port` | `-p` | `3333` | Port for MCP server |
| `--host` | | `127.0.0.1` | Bind address |

---

### `crysa context`

Print the security context snapshot Crysa has built for a project.
Useful for understanding what Crysa knows about your codebase before scanning.

```bash
crysa context ./my-project
crysa context .
```

Output includes: detected framework, language, authentication patterns,
route count, data model count, and role/permission definitions.

---

### `crysa init`

Interactive setup wizard. Writes `.env` and `config.yaml` and prints
ready-to-paste MCP configuration for Claude Code, Cursor, and Hermes Agent.

```bash
crysa init
```

---

### `crysa explain`

Generate a deep, comprehensive writeup for a single finding.

Re-queries the LLM with a structured analysis prompt and produces an executive
summary, full attack scenario, working PoC, business impact, before/after
remediation code, and verification steps.

```bash
# First produce a JSON report
crysa scan ./src --output report.json

# Then explain any finding by its ID
crysa explain report.json CRYSA-A3F2B1
```

Output sections:
- **Executive Summary** — 2-3 sentences for non-technical stakeholders
- **Technical Analysis** — root cause with code-level detail
- **Attack Scenario** — step-by-step narrative of exploitation
- **Proof of Concept** — working curl commands or exploit code
- **Business Impact** — regulatory implications (GDPR, SOC2, PCI-DSS)
- **Remediation** — before/after code diff
- **Verification** — how to confirm the fix is complete

---

### `crysa install-hook`

Install a git pre-commit hook that scans staged changes before every commit.

```bash
crysa install-hook                    # blocks HIGH+ findings (default)
crysa install-hook --severity MEDIUM  # blocks MEDIUM+ findings
crysa install-hook --force            # overwrite existing hook
```

The hook blocks commits when findings at or above the threshold are found
and shows them in the terminal. Bypass with `git commit --no-verify`.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--severity` | `-s` | `HIGH` | Minimum severity that blocks the commit |
| `--force` | `-f` | off | Overwrite an existing hook |

---

## Finding Output

Each finding is structured and actionable:

```
  CRITICAL  •  IDOR  •  HIGH CONFIDENCE
  api/views/orders.py  lines 42-58
┌─ CRYSA-A3F2B1 ─────────────────────────────────────────────────────────────┐
│  Missing ownership check on order update endpoint                           │
│                                                                             │
│  Any authenticated user can update any order by supplying an arbitrary      │
│  order_id. No check verifies the requesting user owns the order before      │
│  the update is applied.                                                     │
│                                                                             │
│  IMPACT: Full horizontal privilege escalation. Attacker can modify,         │
│  cancel, or corrupt any user's orders.                                      │
│                                                                             │
│  REPRODUCTION:                                                              │
│  1. Authenticate as user A                                                  │
│  2. POST /api/orders/update with order_id belonging to B                    │
│  3. Update is applied without authorization error                           │
│                                                                             │
│  FIX: Add ownership check before update:                                    │
│  order = Order.objects.get(id=order_id, user=request.user)                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

Each finding includes:
- **Unique ID** — reference and track findings across scans
- **Vulnerability class** — IDOR, AUTH_BYPASS, PRIVILEGE_ESC, etc.
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Confidence** — HIGH / MEDIUM / LOW
- **Exact location** — file and line numbers
- **Description** — what is vulnerable and why
- **Impact** — what an attacker can actually achieve
- **Reproduction** — step-by-step exploit path
- **Fix** — concrete remediation

---

## Vulnerability Classes

| Class | What Crysa Catches |
|---|---|
| `IDOR` | Missing ownership checks on resource access |
| `AUTH_BYPASS` | Missing or bypassable authentication |
| `PRIVILEGE_ESC` | Horizontal and vertical privilege escalation |
| `MASS_ASSIGN` | Unfiltered request body binding to models |
| `JWT_ISSUE` | Algorithm confusion, missing verification, weak secrets |
| `LOGIC_FLAW` | Price manipulation, race conditions, workflow bypass |
| `DATA_EXPOSURE` | PII in responses, debug endpoints, verbose errors |

To focus on specific classes:

```bash
crysa scan ./src --vuln-class IDOR,PRIVILEGE_ESC
```

---

## Output Formats

### `rich` (default)
Colored, structured terminal output with panels for each finding and a
summary table. Findings stream to the terminal as files complete during
directory scans.

### `json`
Machine-readable JSON with full finding details and a summary block.
JSON and SARIF output go to **stdout** so they are safe to pipe or redirect:

```bash
crysa scan ./src --format json | jq '.findings[].severity'
crysa scan ./src --format json > report.json

# Or use --output to write directly to a file:
crysa scan ./src --output report.json
```

### `sarif`
Valid SARIF 2.1.0 output for integration with GitHub Code Scanning,
VS Code, and any SARIF-compatible security tool.

```bash
crysa scan ./src --format sarif > crysa-results.sarif
# or using --output:
crysa scan ./src --output results.sarif
```

#### GitHub Actions — Code Scanning

```yaml
- name: Crysa Security Scan
  run: crysa scan ./src --output crysa.sarif
  env:
    CRYSA_API_KEY: ${{ secrets.CRYSA_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: crysa.sarif
```

#### GitHub Actions — Fail on HIGH/CRITICAL Findings

```yaml
- name: Crysa Security Gate
  run: crysa --exit-code scan ./src --severity HIGH
  env:
    CRYSA_API_KEY: ${{ secrets.CRYSA_API_KEY }}
```

#### Baseline Mode in CI — Only Alert on New Findings

```yaml
- name: Download baseline
  run: gh release download --name baseline.json || echo '{"findings":[]}' > baseline.json

- name: Crysa Security Gate
  run: crysa --exit-code scan ./src --baseline baseline.json --severity HIGH
  env:
    CRYSA_API_KEY: ${{ secrets.CRYSA_API_KEY }}
```

---

## MCP Integration

Crysa exposes four tools via MCP for seamless integration with AI coding agents:

| Tool | Description |
|---|---|
| `review_diff` | Review a code diff for security vulnerabilities |
| `review_file` | Review an entire file for vulnerabilities |
| `get_context` | Get security context of the codebase |
| `scan_project` | Full project security scan |

### Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "crysa": {
      "command": "crysa",
      "args": ["mcp"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "crysa": {
      "command": "crysa",
      "args": ["mcp"]
    }
  }
}
```

### Hermes Agent

Add to `~/.hermes/config.yaml`:

```yaml
mcp:
  servers:
    crysa:
      command: crysa
      args:
        - mcp
```

---

## Configuration

Crysa works out of the box with zero config beyond the API key.
All settings in `config.yaml` have sane defaults:

```yaml
crysa:
  # LLM Backend — any OpenAI-compatible API
  base_url: "${CRYSA_BASE_URL}"
  model: "${CRYSA_MODEL}"
  api_key: "${CRYSA_API_KEY}"
  max_tokens: 4096
  temperature: 0.1

  # Scanning
  severity_threshold: LOW       # Default minimum severity to store
  confidence_threshold: MEDIUM  # Filter out LOW confidence findings
  chunk_size: 8000              # Token budget per LLM call
  chunk_overlap: 200            # Overlap between chunks for context

  # MCP Server
  mcp_host: "127.0.0.1"
  mcp_port: 3333

  # Watcher
  debounce_ms: 800              # Wait this long after last change before scanning
  max_file_lines: 2000          # Skip files longer than this

  # Output
  default_format: rich
  show_fix: true                # Show fix suggestions
  show_reproduction: true       # Show reproduction steps
```

### Environment Variables

Set your API credentials in `.env` (created by `crysa init`):

```bash
CRYSA_BASE_URL=https://api.openai.com/v1
CRYSA_MODEL=gpt-4o
CRYSA_API_KEY=your_key_here
```

Crysa supports any OpenAI-compatible API: xAI/Grok, Ollama, DeepSeek,
OpenAI, Mistral, or self-hosted models.

#### Verbosity Variables

```bash
CRYSA_VERBOSE=1   # Enable debug output (equivalent to --verbose)
CRYSA_QUIET=1     # Suppress non-finding output (equivalent to --quiet)
```

---

## How It Works

1. **Context Building** — Crysa does a single filesystem traversal of your
   project, reading up to 100 representative source files. It detects your
   framework, authentication mechanisms (decorators, middleware, guards,
   dependency injection), route definitions, data models, and role/permission
   patterns. All regex patterns are pre-compiled at startup. The result is
   cached for the session.

2. **Prompt Construction** — For each file (or diff), Crysa builds a prompt
   containing: the security context snapshot, vulnerability-specific reasoning
   hints for each of the 7 vulnerability classes, the code chunk, and file
   metadata. Large files are split into overlapping chunks with preserved
   line numbers.

3. **Concurrent LLM Reasoning** — For directory scans, files are sent to the
   LLM concurrently (default: 4 threads). LLM calls are I/O-bound, so this
   gives near-linear speedup up to your API's rate limit.

4. **Finding Extraction** — The LLM's JSON response is parsed into structured
   `Finding` objects. If the LLM wraps its JSON in prose or markdown fences,
   Crysa extracts it. Invalid items are skipped without crashing.

5. **Deduplication** — Findings from chunked files are deduplicated: findings
   within 10 lines of each other with the same vulnerability class and title
   are collapsed, keeping the higher-confidence result.

---

## Supported Languages

| Language | Frameworks |
|---|---|
| Python | Django, Flask, FastAPI |
| JavaScript / TypeScript | Express, NestJS, Next.js |
| Go | Gin, Echo |
| Ruby | Rails, Sinatra |
| PHP | Laravel, Symfony |
| Java | Spring Boot |
| Rust | (any) |
| C# | .NET |

---

## Contributing

Crysa is built for the security community.

```bash
git clone https://github.com/crysa/crysa
cd crysa
pip install -e ".[dev]"
python -m pytest tests/
```

Key areas to contribute:

- **Vulnerability hints** — Improve reasoning hints in `crysa/vulns/`
- **Framework support** — Improve context detection in `crysa/engine/context.py`
- **Output formats** — Add new formatters in `crysa/cli.py`
- **Bug fixes** — The test suite in `tests/` covers constants, findings, parser, config, and reviewer logic

```bash
# Run the full test suite
python -m pytest tests/ -q
```

---

## License

MIT use it, fork it, ship it.
