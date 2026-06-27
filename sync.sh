#!/bin/bash

# MuteMaster Hunt — Sync + Push
# Updates both local Claude install and GitHub in one command
# Usage: ./sync.sh "what you changed"

set -e

SKILL_SRC="$HOME/Desktop/agent-skills/skills/mutemaster-hunt"
SKILL_LIVE="$HOME/.claude/skills/mutemaster-hunt"
REPO="$HOME/Desktop/agent-skills"

# Require a commit message
if [ -z "$1" ]; then
  echo "Usage: ./sync.sh \"describe what you changed\""
  exit 1
fi

echo "→ Syncing to local Claude install..."
cp -r "$SKILL_SRC/." "$SKILL_LIVE/"
echo "✓ ~/.claude/skills/mutemaster-hunt updated"

echo "→ Pushing to GitHub..."
cd "$REPO"
git add .
git commit -m "$1"
git push
echo "✓ github.com/Zaphh-Tech/agent-skills updated"

echo ""
echo "Done. Reinstall command for others:"
echo "npx -y skills add Zaphh-Tech/agent-skills --skill mutemaster-hunt --agent claude-code"
