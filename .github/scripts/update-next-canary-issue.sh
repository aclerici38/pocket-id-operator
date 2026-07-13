#!/usr/bin/env bash
set -euo pipefail

# Renders the pocket-id `next` compatibility canary dashboard issue.
#
# Idempotent: reads current state from hidden markers in the existing issue,
# overlays any *_NEW values the caller supplies, re-renders, and creates the
# issue (locked) on first run. The `resolve` job calls it every hour with only
# CHECKED_AT_NEW (heartbeat); the `e2e` job calls it with the full result.
#
# Required env: CANARY_LABEL, CANARY_ASSIGNEE, OPERATOR_IMAGE, GH_TOKEN
# Optional env: STATUS_NEW (passing|failing), TESTED_DIGEST_NEW, TESTED_AT_NEW,
#               TESTED_RUN_NEW, CHECKED_AT_NEW

: "${CANARY_LABEL:?}"
: "${CANARY_ASSIGNEE:?}"
: "${OPERATOR_IMAGE:?}"

NUM="$(gh issue list --label "$CANARY_LABEL" --state all --limit 1 --json number -q '.[0].number // empty' || true)"

BODY=""
if [ -n "$NUM" ]; then
  BODY="$(gh issue view "$NUM" --json body -q .body)"
fi

marker() { # key -> current value from the existing body ("" if absent)
  printf '%s' "$BODY" | grep -oE "state:$1=[^ ]+" | head -1 | cut -d= -f2- || true
}

STATUS="${STATUS_NEW:-$(marker status)}"
TDIGEST="${TESTED_DIGEST_NEW:-$(marker tested-digest)}"
TAT="${TESTED_AT_NEW:-$(marker tested-at)}"
TRUN="${TESTED_RUN_NEW:-$(marker tested-run)}"
CAT="${CHECKED_AT_NEW:-$(marker checked-at)}"

case "$STATUS" in
  passing) BADGE="✅ **PASSING**" ;;
  failing) BADGE="❌ **FAILING**" ;;
  *)       BADGE="⏳ **PENDING** (no run recorded yet)" ;;
esac

NEW_BODY="$(cat <<EOF
## pocket-id \`next\` compatibility canary

<!-- state:status=${STATUS:-unknown} state:tested-digest=${TDIGEST:-none} state:tested-at=${TAT:-never} state:tested-run=${TRUN:-none} state:checked-at=${CAT:-never} -->

${BADGE}

|              |                                                          |
| ------------ | -------------------------------------------------------- |
| image        | \`ghcr.io/pocket-id/pocket-id:next-distroless@${TDIGEST}\` |
| operator     | \`${OPERATOR_IMAGE}\`                                     |
| last tested  | ${TAT:-never} ([run](${TRUN}))                            |
| last checked | ${CAT:-never}                                            |

---
_Automated hourly by \`.github/workflows/test-e2e-next.yaml\`; this issue is locked, do not edit._
_The e2e suite only runs when the \`next-distroless\` digest changes; \`last checked\` updates every hour regardless._
_While failing, @${CANARY_ASSIGNEE} is assigned; the assignment clears on the next green run._
EOF
)"

if [ -z "$NUM" ]; then
  gh label create "$CANARY_LABEL" --color BFD4F2 \
    --description "pocket-id next e2e canary dashboard" 2>/dev/null || true
  NUM="$(gh issue create \
    --title "pocket-id \`next\` compatibility canary" \
    --label "$CANARY_LABEL" \
    --body "$NEW_BODY" | grep -oE '[0-9]+$')"
  gh issue lock "$NUM" 2>/dev/null || true
else
  gh issue edit "$NUM" --body "$NEW_BODY"
fi

# Assignee and reopen state only change when a real e2e result is written.
if [ -n "${STATUS_NEW:-}" ]; then
  gh issue reopen "$NUM" 2>/dev/null || true
  if [ "$STATUS_NEW" = "passing" ]; then
    gh issue edit "$NUM" --remove-assignee "$CANARY_ASSIGNEE" 2>/dev/null || true
  else
    gh issue edit "$NUM" --add-assignee "$CANARY_ASSIGNEE"
  fi
fi
