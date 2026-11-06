# FourPaws project instructions

Read docs/CODEX_HANDOFF.md and README.md before editing. The handoff records the latest user decisions and known incomplete work.

- Communicate in clear, concise Hebrew. Use English for code and exact technical identifiers.
- Continue the existing application. Do not rebuild from a starter or change frameworks without a concrete need.
- The user rejected the current green desktop-looking design and selected a colorful, friendly, mobile-first direction. That redesign is NOT implemented yet.
- Work locally for now. Finish local changes and validation before trying GitHub again. Do not deploy the live Site until the user authorizes publication again.
- `admin` refers to the FourPaws application user, not a GitHub/Google account. No default password, password reset, or special admin role is authorized by this name.
- Use Google Gemini and Google Search as already selected. Do not switch AI provider without a user request.
- Never include credentials, API keys, session tokens, user data, .env files, or data/ in source control or handoff artifacts. Configure runtime secrets through a secure environment mechanism; do not print their values.
- Preserve existing data and unrelated behavior. Ask before deleting user data, changing production access, or other hard-to-reverse actions.
- Medical AI is preliminary guidance only: no photo-based assurance that a veterinarian is unnecessary, no prescriptions/doses, no invasive procedures. Keep emergency escalation before the AI request.
- Verify evolving product/API behavior with current official documentation. Never invent prices, distances, clinical facts, capabilities, or successful test/deployment outcomes.
- Use `npm test`, `npm run build`, and `npm run validate` for relevant changes. Browser QA must cover mobile navigation and genuine form submissions, not just screenshots or VM rendering.
- Keep dependency and architecture changes minimal. There are no npm runtime dependencies in the Node backend.
- GitHub writes previously failed with 403. Do not repeat failed authorization detours or claim a push succeeded without reading the resulting commit/ref.
