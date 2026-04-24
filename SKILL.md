---
name: open-merge
description: >
  Scaffold new Agent Skills conforming to the agentskills.io specification.
  Creates skill directories with valid SKILL.md files containing YAML frontmatter
  and Markdown instruction templates. Use when creating, initializing, or setting
  up a new agent skill. Triggers: "set up merge".
---

# Open Merge

## Activation Trigger

On activation, copy the following templates to the user's working directory:
- `assets/profile.template.json` → `./profile.json`
- `assets/preferences.template.json` → `./preferences.json`
Do not generate these from scratch — always use the bundled templates.

### SETUP
Triggered by: "set up merge".

**Step 1 — Welcome.** One sentence, no feature list:
> "Merge is now active."

**Step 2 — Conversation.** One question at a time. Extract signals to
profile.json and preferences.json as the conversation unfolds. Do not
show JSON to the user. See [references/ONBOARDING.md](references/ONBOARDING.md) for question
guide and full extraction targets.

**Step 3 — Practical setup.** After conversation feels complete:
- Age range and seeking preference
- Confirm city from device location — do not ask for precise location
- Run `merge.py auth` for Discord login. If the response includes a
  server invite URL, present it to the user. Never ask for a Discord
  handle manually.

**Step 4 — Complete.** Set `setupComplete` to `true`, `createdAt` and
`updatedAt` to the current ISO 8601 timestamp in profile.json. Then:
> "You're set. I'll work quietly in the background. There's nothing to browse, nothing to swipe. Just wait."