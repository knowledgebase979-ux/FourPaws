# FourPaws project instructions

Read docs/CODEX_HANDOFF.md and README.md before editing. The handoff records the latest user decisions and known incomplete work.

- Communicate in clear, concise Hebrew. Use English for code and exact technical identifiers.
- Continue the existing application. Do not rebuild from a starter or change frameworks without a concrete need.
- The user selected a colorful, friendly, mobile-first direction. The 7.11.2026 teal/yellow palette was superseded on 13.11.2026 by the comic style described below. Keep five primary navigation sections and avoid duplicated content.
- The user authorized publication of completed changes. The existing Site is public; preserve its audience and identity. Run focused validation and publish completed updates.
- `admin` refers to the FourPaws application user, not a GitHub/Google account. No default password, password reset, or special admin role is authorized by this name.
- Use Google Gemini and Google Search as already selected. Do not switch AI provider without a user request.
- Never include credentials, API keys, session tokens, user data, .env files, or data/ in source control or handoff artifacts. Configure runtime secrets through a secure environment mechanism; do not print their values.
- Preserve existing data and unrelated behavior. Ask before deleting user data, changing production access, or other hard-to-reverse actions.
- Medical AI is preliminary guidance only: no photo-based assurance that a veterinarian is unnecessary, no prescriptions/doses, no invasive procedures. Keep emergency escalation before the AI request.
- Verify evolving product/API behavior with current official documentation. Never invent prices, distances, clinical facts, capabilities, or successful test/deployment outcomes.
- Use `npm test`, `npm run build`, and `npm run validate` for relevant changes. When browser tools are available, verify mobile navigation and genuine form submissions; report unavailable browser verification honestly. The user requested concise focused checks.
- Keep dependency and architecture changes minimal. There are no npm runtime dependencies in the Node backend.
- Publishing to GitHub: `git push` from the Bash tool is denied in cloud sessions, so do not retry it. Push with the GitHub MCP tool `mcp__github__push_files` (owner `knowledgebase979-ux`, repo `FourPaws`, the session's development branch), which the user approved. It takes whole file contents, so push only the changed files. Afterwards read the branch back with `get_file_contents` and compare `git hash-object` to the returned sha before claiming success.
- Visual style (13.11.2026): comic/ink-sketch. White/gray surfaces, thick black outlines and brush-like hand-drawn corners, hard offset shadows. Color (red `#e63946`, blue `#1d4ed8`) only on buttons. No yellow.
