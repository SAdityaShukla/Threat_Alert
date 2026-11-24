#!/usr/bin/env bash
# Runs the 22 self-check steps from the task paper against a freshly
# started server and prints PASS/FAIL for each one.
#
# Usage:  ./selfcheck.sh            (starts and stops the server itself)
#         BASE=http://localhost:8080 ./selfcheck.sh --no-start
#
# Needs: curl and jq.

set -u

BASE="${BASE:-http://localhost:8080}"
START_SERVER=1
[ "${1:-}" = "--no-start" ] && START_SERVER=0

PASS=0
FAIL=0
SERVER_PID=""

cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null
		wait "$SERVER_PID" 2>/dev/null
	fi
}
trap cleanup EXIT

if [ "$START_SERVER" -eq 1 ]; then
	go build -o /tmp/threat-alert-api . || exit 1
	/tmp/threat-alert-api &
	SERVER_PID=$!
	for _ in $(seq 1 50); do
		curl -s -o /dev/null "$BASE/alerts" && break
		sleep 0.1
	done
fi

# check <step> <description> <actual> <expected>
check() {
	if [ "$3" = "$4" ]; then
		printf 'step %-3s PASS  %-42s %s\n' "$1" "$2" "$3"
		PASS=$((PASS + 1))
	else
		printf 'step %-3s FAIL  %-42s got %s want %s\n' "$1" "$2" "$3" "$4"
		FAIL=$((FAIL + 1))
	fi
}

# post/get write the body to /tmp/body and echo the status code.
post() { curl -s -o /tmp/body -w '%{http_code}' -X POST "$BASE$1" "${@:2}"; }
get() { curl -s -o /tmp/body -w '%{http_code}' "$BASE$1" "${@:2}"; }
field() { jq -r "$1" /tmp/body; }

echo "=== self-check against $BASE ==="

# 1
code=$(post /register -d '{"orgName":"Acme","name":"Asha","email":"asha@acme.test"}')
check 1 "register Acme" "$code" 201
check 1 "role is admin" "$(field .role)" admin
A_ADMIN=$(field .token)

# 2
code=$(post /register -d '{"orgName":"Beta","name":"Ravi","email":"ravi@beta.test"}')
check 2 "register Beta" "$code" 201
B_ADMIN=$(field .token)

# 3
code=$(post /register -d '{"orgName":"Gamma","name":"Gita","email":"not-an-email"}')
check 3 "bad email rejected" "$code" 400

# 4
code=$(post /users -H "Authorization: Bearer $A_ADMIN" -d '{"name":"Vik","email":"vik@acme.test","role":"viewer"}')
check 4 "admin adds viewer" "$code" 201
check 4 "role is viewer" "$(field .role)" viewer
A_VIEWER=$(field .token)

# 5
code=$(post /users -H "Authorization: Bearer $A_VIEWER" -d '{"name":"Xia","email":"xia@acme.test","role":"admin"}')
check 5 "viewer cannot add user" "$code" 403

# 6
code=$(post /users -d '{"name":"Xia","email":"xia@acme.test","role":"admin"}')
check 6 "no token" "$code" 401

# 7
code=$(post /apps -H "Authorization: Bearer $A_ADMIN" -d '{"name":"Acme Pay","platform":"android"}')
check 7 "admin adds app" "$code" 201
APP_KEY=$(field .appKey)

# 8
code=$(post /apps -H "Authorization: Bearer $A_ADMIN" -d '{"name":"Acme Web","platform":"windows"}')
check 8 "bad platform rejected" "$code" 400

# 9
code=$(post /alerts -H "X-App-Key: $APP_KEY" -d '{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}')
check 9 "new alert" "$code" 201
check 9 "count is 1" "$(field .count)" 1
check 9 "status is open" "$(field .status)" open
ALERT_ID=$(field .id)

# 10
code=$(post /alerts -H "X-App-Key: $APP_KEY" -d '{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}')
check 10 "repeat alert" "$code" 200
check 10 "count is 2" "$(field .count)" 2
check 10 "same id" "$(field .id)" "$ALERT_ID"

# 11
code=$(post /alerts -H "X-App-Key: $APP_KEY" -d '{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":9}')
check 11 "severity out of range" "$code" 400

# 12
code=$(post /alerts -H "X-App-Key: wrong-key" -d '{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}')
check 12 "wrong app key" "$code" 401

# 13
code=$(get /alerts -H "Authorization: Bearer $A_VIEWER")
check 13 "viewer lists alerts" "$code" 200
check 13 "1 alert for Acme" "$(field '.alerts | length')" 1

# 14
code=$(get /alerts -H "Authorization: Bearer $B_ADMIN")
check 14 "Beta lists alerts" "$code" 200
check 14 "0 alerts for Beta" "$(field '.alerts | length')" 0
check 14 "empty list is []" "$(jq -c .alerts /tmp/body)" "[]"

# 15
code=$(get "/alerts/$ALERT_ID" -H "Authorization: Bearer $B_ADMIN")
check 15 "Beta cannot read Acme alert" "$code" 404

# 16
code=$(post "/alerts/$ALERT_ID/resolve" -H "Authorization: Bearer $A_VIEWER")
check 16 "viewer cannot resolve" "$code" 403

# 17
code=$(post "/alerts/$ALERT_ID/resolve" -H "Authorization: Bearer $B_ADMIN")
check 17 "Beta resolving Acme alert" "$code" 404

# 18
code=$(post "/alerts/$ALERT_ID/resolve" -H "Authorization: Bearer $A_ADMIN")
check 18 "admin resolves" "$code" 200
check 18 "status is resolved" "$(field .status)" resolved

# 19
code=$(post "/alerts/$ALERT_ID/resolve" -H "Authorization: Bearer $A_ADMIN")
check 19 "resolve again" "$code" 409

# 20
code=$(post /alerts -H "X-App-Key: $APP_KEY" -d '{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}')
check 20 "new alert after resolve" "$code" 201
check 20 "count is 1" "$(field .count)" 1
NEW_ID=$(field .id)
if [ "$NEW_ID" != "$ALERT_ID" ]; then
	check 20 "a new id" ok ok
else
	check 20 "a new id" "$NEW_ID" "something other than $ALERT_ID"
fi

# 21
code=$(get "/alerts?status=open" -H "Authorization: Bearer $A_ADMIN")
check 21 "list open alerts" "$code" 200
check 21 "1 open alert" "$(field '.alerts | length')" 1

# 22
seq 50 | xargs -P 50 -I{} curl -s -o /dev/null -X POST "$BASE/alerts" \
	-H "X-App-Key: $APP_KEY" \
	-d '{"deviceId":"d2","threatType":"FRIDA_DETECTED","severity":4}'
get "/alerts?status=open" -H "Authorization: Bearer $A_ADMIN" >/dev/null
check 22 "one alert for d2" "$(jq '[.alerts[] | select(.deviceId=="d2")] | length' /tmp/body)" 1
check 22 "count is 50" "$(jq '[.alerts[] | select(.deviceId=="d2")][0].count' /tmp/body)" 50

echo "=== passed: $PASS   failed: $FAIL ==="
[ "$FAIL" -eq 0 ]
