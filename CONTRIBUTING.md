# Contributing

Thank you for helping improve forensicagent. Keep changes focused, preserve
forensic evidence, and use synthetic or openly licensed fixtures only.

## Development setup (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --editable ".[dev]"
```

Run the same core checks as CI:

```powershell
.venv\Scripts\ruff.exe check .
.venv\Scripts\python.exe -m pytest --basetemp .pytest_cache/tmp
```

Add a focused regression test for behavior changes. Do not commit downloaded
corpora, tool output, API keys, credentials, or evidence from a real case.
Document third-party data with its source URL, pinned revision, and license.

## Pull requests

- Explain the user-visible problem and the chosen behavior.
- Keep selector-ranking metrics separate from end-to-end finding accuracy.
- Do not silently suppress findings; analyst labels must remain auditable.
- Do not add automatic downloads without HTTPS, a pinned version, and a
  verified SHA-256 digest.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in a public issue or pull request.
