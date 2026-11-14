# FourPaws project instructions

Read docs/CODEX_HANDOFF.md and README.md before editing. The handoff records the latest user decisions and known incomplete work.

- Communicate in clear, concise Hebrew. Use English for code and exact technical identifiers.
- Continue the existing application. Do not rebuild from a starter or change frameworks without a concrete need.
- The user selected a colorful, friendly, mobile-first direction. On 7.11.2026 the user rejected the teal palette and reported unreadable text and mobile layout issues. The latest revision uses warm white surfaces, deep navy and apricot accents; visual approval is still pending. Keep five primary navigation sections and avoid duplicated content.
- The user authorized publication of completed changes. The existing Site is public; preserve its audience and identity. Run focused validation and publish completed updates.
- `admin` refers to the FourPaws application user, not a GitHub/Google account. No default password, password reset, or special admin role is authorized by this name.
- Use Google Gemini for consultations and synthesis, and Exa Lite for web search, as requested on 7.11.2026. Never fall back automatically to paid Google Search tools.
- Never include credentials, API keys, session tokens, user data, .env files, or data/ in source control or handoff artifacts. Configure runtime secrets through a secure environment mechanism; do not print their values.
- Preserve existing data and unrelated behavior. Ask before deleting user data, changing production access, or other hard-to-reverse actions.
- Registration creates a pet passport: require name, age and breed/type plus a login nickname and a new 6–8 character password containing English letters and digits. Email/photo/weight and other pet fields are optional. Preserve login compatibility for existing longer passwords. Keep info/photo research separate from shopping and apply shopping filters/sort on the server. Personalize to the active passport without sending private notes/contact details in shopping searches.
- Medical AI is preliminary guidance only: no photo-based assurance that a veterinarian is unnecessary, no prescriptions/doses, no invasive procedures. Keep emergency escalation before the AI request.
- Verify evolving product/API behavior with current official documentation. Never invent prices, distances, clinical facts, capabilities, or successful test/deployment outcomes.
- Use `npm test`, `npm run build`, and `npm run validate` for relevant changes. When browser tools are available, verify mobile navigation and genuine form submissions; report unavailable browser verification honestly. The user requested concise focused checks.
- Keep dependency and architecture changes minimal. There are no npm runtime dependencies in the Node backend.
- GitHub writes previously failed with 403. Do not repeat failed authorization detours or claim a push succeeded without reading the resulting commit/ref.

- Visual style (13.11.2026): preserve the comic/ink-sketch design from GitHub main: white/gray surfaces, thick black outlines, hard offset shadows; red #e63946 and blue #1d4ed8 on buttons only. No yellow.
- Before deployment, compare GitHub main with the current Site source. Preserve accepted functionality (Exa search, separate info/shopping, pet passport registration, server filters) when integrating design changes.
