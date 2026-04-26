---
name: open-merge
description: >
  Scaffold new Agent Skills conforming to the agentskills.io specification.
  Creates skill directories with valid SKILL.md files containing YAML frontmatter
  and Markdown instruction templates. Use when creating, initializing, or setting
  up a new agent skill. Triggers: "set up merge", "start looking", "find me someone", "pause my matching", "delete my profile", "preview my intro".
  Do NOT trigger for general relationship advice, friendship, or
  professional networking.
metadata:
  telegram_bot_username: "OpenMergeBot"
  broker_url: "http://localhost:8080"
---

# Open Merge

## Activation Trigger

On activation, copy the following templates to the user's working directory:
- `assets/profile.template.json` → `./assets/profile.json`
- `assets/preferences.template.json` → `./assets/preferences.json`
Do not generate these from scratch — always use the bundled templates.

### SETUP
Triggered by: "set up merge", "start over"

**Step 1 — Welcome.** One sentence, no feature list:
> "Merge is now active. I'm going to help you find someone — quietly, privately. Before I can do anything useful, talk to me. What are you looking for?"

**Step 2 — Conversation.** One question at a time. Extract signals to
profile.json and preferences.json as the conversation unfolds. Do not
show JSON to the user. See [references/ONBOARDING.md](references/ONBOARDING.md) for question
guide and full extraction targets.

**Step 3 — Practical setup.** After conversation feels complete:
- User's gender (M, F, or NB)
- User's actual age (required, must be ≥ 18)
- Age range and seeking preference
- Confirm city from device location — do not ask for precise location

**Step 4 — Authorization & Age verification.** Non-negotiable:
- Run `uv run scripts/merge.py auth --profile assets/profile.json` for Telegram login.
  The command opens a deep-link to the Merge bot; the user taps Start in
  Telegram, and the bot confirms their identity. Never ask for a Telegram
  handle manually.

**Step 5 — Introduction card.** Generate and preview before going live:
- Run `uv run scripts/merge.py card --profile assets/profile.json --output assets/card.txt` to build the introduction card.
- Show the card text to the user: "Here's how you'll be introduced when there's a match."
- If the user wants changes, update profile.json and regenerate.

**Step 6 — Complete.** Set `setupComplete` to `true`, `createdAt` and
`updatedAt` to the current ISO 8601 timestamp in profile.json. Then:
- Run `uv run scripts/merge.py upload --profile assets/profile.json --preferences assets/preferences.json` for signal upload.
> "You're set. I'll work quietly in the background. There's nothing to browse, nothing to swipe. Just wait."

---

### SIGNAL
Triggered by: "find me someone", "start looking".
Check setupComplete and ageVerified. If either false, run SETUP.
- Run `uv run scripts/merge.py upload --profile assets/profile.json --preferences assets/preferences.json` for signal upload.
> "Your signal is live. I'll let you know when something comes through."

---

### PAUSE
Triggered by: "pause my matching", "stop looking", "go offline".

- Run `uv run scripts/merge.py pause` to remove the active signal.
- The profile and preferences remain intact — only the signal is removed.
> "Signal removed. Tell me when you're ready again."

---

### CARD
Triggered by: "preview my intro".
- If `assets/card.txt` exists, read it and show the card text to the user.
- If `assets/card.txt` does not exist, run `uv run scripts/merge.py card --profile assets/profile.json --output assets/card.txt` to generate it first, then show.

---

### DELETE
Triggered by: "delete my profile", "remove me from Merge", "I'm done with this".

> "This will remove your signal, delete your broker account, and clean up local files. Your Telegram conversations stay. Want to proceed?"

On confirm:
- Run `uv run scripts/merge.py delete` to delete the broker account and remove local files.
> "Done. Everything's gone from Merge's side. Good luck."