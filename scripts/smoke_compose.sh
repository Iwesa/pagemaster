#!/bin/sh
# End-to-end smoke test of the running docker compose stack (dry-run mode).
#
# alert -> page in the dry-run outbox -> AWAITING_APPROVAL -> reply through /api/demo/reply -> RESOLVED
#
# Usage (after `docker compose up -d --wait`):  scripts/smoke_compose.sh
# Environment:
#   BASE_URL              default http://127.0.0.1:8000
#   ALERT_WEBHOOK_SECRET  sent as "Authorization: Bearer ..." on the alert when set
#   SMOKE_TIMEOUT_SECONDS per wait, default 90
# Needs curl and python3 (used to read JSON; no jq).
set -eu

BASE_URL=${BASE_URL:-http://127.0.0.1:8000}
TIMEOUT=${SMOKE_TIMEOUT_SECONDS:-90}
body_file=$(mktemp)
trap 'rm -f "$body_file"' EXIT

log() {
    echo "smoke: $*"
}

fail() {
    echo "smoke: FAIL: $*" >&2
    exit 1
}

# wait_until <description> <command...>: run the command once a second until it succeeds.
wait_until() {
    description=$1
    shift
    elapsed=0
    while ! "$@"; do
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$TIMEOUT" ]; then
            fail "timed out after ${TIMEOUT}s waiting for $description"
        fi
        sleep 1
    done
}

ready() {
    curl -fsS "$BASE_URL/readyz" >/dev/null 2>&1
}

# post_json <path> <json> [bearer]: prints the HTTP status, leaves the response body in $body_file.
post_json() {
    if [ -n "${3:-}" ]; then
        curl -sS -o "$body_file" -w '%{http_code}' -X POST \
            -H 'Content-Type: application/json' -H "Authorization: Bearer $3" \
            -d "$2" "$BASE_URL$1"
    else
        curl -sS -o "$body_file" -w '%{http_code}' -X POST \
            -H 'Content-Type: application/json' \
            -d "$2" "$BASE_URL$1"
    fi
}

# outbox_has_page <incident_id>: success when the outbox holds an INC- page for that incident.
outbox_has_page() {
    curl -fsS "$BASE_URL/api/demo/outbox?limit=100" | python3 -c '
import json, sys
wanted = sys.argv[1]
for message in json.load(sys.stdin):
    if message.get("incident_id") == wanted and message["text"].startswith("INC-"):
        print(message["text"])
        sys.exit(0)
sys.exit(1)
' "$1"
}

# incident_state <incident_id>: prints the state, or nothing when the incident is not listed.
incident_state() {
    curl -fsS "$BASE_URL/api/incidents" | python3 -c '
import json, sys
wanted = sys.argv[1]
for row in json.load(sys.stdin):
    if row["incident_id"] == wanted:
        print(row["state"])
        break
' "$1"
}

# wait_for_state <incident_id> <state>: fails at once if the incident ends in any other final state.
wait_for_state() {
    elapsed=0
    while :; do
        state=$(incident_state "$1" || true)
        if [ "$state" = "$2" ]; then
            return 0
        fi
        case "$state" in
            RESOLVED | FAILED | EXPIRED | NO_ACTION | BLOCKED_BY_TRIPWIRE)
                fail "incident $1 ended in $state while waiting for $2"
                ;;
        esac
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$TIMEOUT" ]; then
            fail "timed out after ${TIMEOUT}s waiting for incident $1 to reach $2 (last state: ${state:-unknown})"
        fi
        sleep 1
    done
}

log "waiting for $BASE_URL/readyz"
wait_until "/readyz to answer 200" ready

error_code="SMOKE_$(date +%s)"
alert="{\"service_name\":\"auth-db\",\"error_code\":\"$error_code\",\"summary\":\"compose smoke test\"}"
log "posting alert $error_code"
status=$(post_json /webhooks/alerts "$alert" "${ALERT_WEBHOOK_SECRET:-}")
[ "$status" = "202" ] || fail "POST /webhooks/alerts returned $status: $(cat "$body_file")"
incident_id=$(python3 -c 'import json, sys; print(json.load(sys.stdin)["incident_id"])' <"$body_file")
log "incident $incident_id accepted"

page_sent() {
    outbox_has_page "$1" >/dev/null
}
wait_until "the page for incident $incident_id in /api/demo/outbox" page_sent "$incident_id"
log "page: $(outbox_has_page "$incident_id")"

wait_for_state "$incident_id" AWAITING_APPROVAL
log "incident is AWAITING_APPROVAL"

status=$(post_json /api/demo/reply "{\"incident_id\":\"$incident_id\",\"choice\":1}")
[ "$status" = "202" ] || fail "POST /api/demo/reply returned $status: $(cat "$body_file")"

wait_for_state "$incident_id" RESOLVED
log "OK: incident $incident_id RESOLVED"
