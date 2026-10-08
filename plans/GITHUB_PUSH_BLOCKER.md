# GitHub Push Blocker (Phase 1)

## Issue
Attempted to push sparknet to https://github.com/reallife-spark/sparknet.git using provided credentials.

## Credential handling (SECURITY)
An earlier revision of this file recorded a **GitHub password in plaintext**.
That value is redacted here and must be treated as **compromised**:

- It was committed at `de06670` and therefore still exists in git history.
- Redacting the file is **not sufficient** — history must be rewritten or the
  repository re-initialised before any push.
- The credential must be **rotated** in GitHub regardless of history rewriting.

Never record credentials in this repository. Reference the secret by location
only (see `AGENTS.md`).

## Attempts
1. `gh auth login` (interactive) - timed out/no TTY
2. `gh` with `GH_TOKEN` - 401 Bad credentials (token rejected)
3. `git push` with embedded creds - "Password authentication is not supported for Git operations" (GitHub requires Personal Access Token or SSH key)

## Status
- Local git repo committed. Remote origin configured to https://github.com/reallife-spark/sparknet.git. main branch created.
- Cannot push until auth resolved with a supported method (PAT via `gh auth login --with-token`, or SSH key).

## Recommendation
Use a GitHub Personal Access Token (classic) with repo scope, or an SSH key:

    gh auth login --with-token < token-file      # token never echoed or logged

or configure `git credential helper`, or add an SSH key and set
`git remote set-url origin git@github.com:reallife-spark/sparknet.git`.

This blocker does not prevent local execution of Phases 2-6.