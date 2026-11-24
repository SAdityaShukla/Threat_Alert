# Threat Alert API

A small in-memory server for the Bugsmirror backend intern task. Companies
register, admins add users and apps, the SDK reports threats with an app
key, and people from the company list and resolve their own alerts.

Go 1.22+, standard library only. `go.mod` has no `require` lines.

## How to run

```bash
# from inside this folder
go run .
# listens on http://localhost:8080

# a different port
PORT=9090 go run .
```

Tests:

```bash
go test ./...
go test -race ./...     # passes on my machine
go vet ./...
gofmt -l .              # prints nothing
```

The whole self-check table from the task paper is scripted, so it can be
run in one command (needs `curl` and `jq`; it starts and stops the server
itself):

```bash
./selfcheck.sh
# => 36 assertions across the 22 steps, "passed: 36   failed: 0"
```

Docker (bonus):

```bash
docker build -t threat-alert-api .
docker run -p 8080:8080 threat-alert-api
```

## Project structure

| File | What it does |
| --- | --- |
| `go.mod` | Module name and `go 1.22`. No dependencies. |
| `main.go` | Reads `PORT` (default 8080), builds the server, starts it, and shuts down cleanly on Ctrl+C. |
| `models.go` | `Company`, `User`, `App`, `Alert` structs with their JSON tags, the role/status/platform constants, and `RFC3339Time` so timestamps print as UTC seconds. |
| `store.go` | All in-memory maps, ID counters, one `sync.RWMutex`, and every data operation (register, create user/app, report alert, resolve, list, get). |
| `auth.go` | Reads `Authorization: Bearer <token>` and `X-App-Key: <appKey>`, looks the caller up, and does the admin-only check. |
| `handlers.go` | The seven HTTP handlers, the route table on Go 1.22's method-aware `ServeMux`, and the optional paging helper. |
| `utils.go` | JSON response and error helpers, body decoding, `crypto/rand` hex generation, the small input validators, and the wrapper that turns Go's own 404/405 bodies into JSON. |
| `handlers_test.go` | The three required tests plus extra ones for repeat alerts, check order, severity, credential randomness, list order and the default error bodies. |
| `selfcheck.sh` | Runs the paper's 22 self-check steps against a live server and prints PASS/FAIL per step. |
| `Dockerfile` | Bonus: builds a static binary and runs it on a distroless image. |
| `.gitignore` | Keeps the compiled binary out of the repository. |

Request flow: `main.go` → `ServeMux` route → handler in `handlers.go` →
authentication in `auth.go` → validation in `utils.go` → data operation in
`store.go` → JSON written back by `writeJSON`.

## What works and what does not

Works, and I checked each one by running it:

- All seven routes with the exact field names and status codes from the paper.
- Register creates a company plus its first admin; `/users` and `/apps` only
  ever use the company taken from the caller's token.
- Repeat alerts: an open alert with the same app, `deviceId` and `threatType`
  gets `count + 1`, a new `lastSeen`, and comes back with 200 and the same id.
  Severity and `firstSeen` are kept. Once resolved, the next report of the
  same threat creates a new alert with count 1 and 201.
- Check order 401 → 403 → 400 → 404. A viewer sending an invalid body still
  gets 403, not 400.
- Company isolation: another company's alert is 404 on both `GET /alerts/{id}`
  and `/resolve`, and never appears in a list.
- `GET /alerts` sorts by `lastSeen` newest first, filters on
  `?status=open|resolved`, rejects any other status with 400, and returns
  `[]` rather than `null` when empty.
- Resolve sets `status` and `resolvedBy`; a second resolve is 409.
- Tokens and app keys are 16 bytes from `crypto/rand` as 32 hex characters.
- 50 identical reports sent together end up as one alert with count 50
  (`go test -race` and `./selfcheck.sh` step 22 both check this).
- All timestamps are UTC RFC 3339, e.g. `"2026-11-24T09:57:13Z"`.
- Bonus: `GET /summary` (open alerts per severity, caller's company only),
  `?limit=` and `?offset=` on `GET /alerts`, a Dockerfile, and clean shutdown
  on Ctrl+C.

What does not, or is deliberately out of scope:

- Everything is in memory, so all data is lost on restart. I did not do the
  "save to a JSON file" bonus.
- There is no login route. Tokens come from `/register` and `/users` and never
  expire; there is no way to rotate or revoke one.
- Email is only checked for an `@`, exactly as the paper asks. Duplicate
  emails are allowed, since nothing in the paper says they are not.
- One `RWMutex` guards the whole store. That is correct but it does mean every
  write is serialised; with real traffic I would shard per company.
- No pagination on `/alerts` by default (only if `?limit=` is passed), no rate
  limiting, and no HTTPS - those would be handled in front of this service.

## How AI helped

- Tools I used: Claude (Opus), used from the terminal in the project folder.

- Two prompts I used (paste them as you typed them):

  1. "You are an experienced Golang backend engineer. I have a time-constrained
     backend developer internship coding assessment that must be completed
     within 3 hours. I have attached the official assignment PDF. Your job is to
     help me implement the complete solution in Go, following the PDF EXACTLY.
     Standard library only, no third-party packages, go.mod with no require
     lines, Go 1.22 method-aware ServeMux, all data in memory, crypto/rand for
     tokens and app keys. Implement all seven endpoints, rules R1-R10, and the
     three mandatory tests, then verify the 22 self-check scenarios."

  2. "Validation order is critical: always check authentication (401), then
     role (403), then input (400), then resource existence (404). A user from
     company B asking for company A's alert must get 404, not 403. Walk through
     each handler and show me where each of those four checks happens, and tell
     me anything that could make the company's automated test script fail."

- One thing the AI got wrong, and how I found and fixed it: the first version
  returned Go's default `404 page not found` and `405 method not allowed`
  bodies, which are plain text. R4 says every error must be JSON. I only
  noticed because I ran `curl -i localhost:8080/nope` by hand while going
  through the self-check and saw `Content-Type: text/plain`. The fix is the
  `jsonErrors` wrapper in `utils.go`: it keeps the status code and the `Allow`
  header that Go sets, but replaces the body with `{"error": "..."}`. I added
  `TestDefaultErrorsAreJSON` so it cannot come back. A second, smaller one: an
  early draft stored timestamps as plain `time.Time`, which marshals with
  nanoseconds (`2026-11-24T09:57:13.482913Z`) instead of the
  `2026-11-23T10:00:00Z` shape in the paper. That is why `RFC3339Time` in
  `models.go` has its own `MarshalJSON`.

- One part I wrote or changed myself without AI: the `openAlerts` map in
  `store.go`. The first version looked for a duplicate by scanning every alert
  in the map on each report, which is O(n) per request and gets slower as
  alerts pile up. I replaced it with a `map[dedupeKey]string` index keyed on
  app + device + threat type that only ever holds *open* alerts, so a lookup is
  O(1), and resolving an alert deletes its key (`store.go:252`) - which is also
  what makes "a resolved threat starts a brand new alert" fall out for free
  instead of needing a second check.

## Questions

**1. Two identical alerts arrive at the same moment. Point to the lines in your
code that make sure only one alert is created.**

Everything is in `Store.ReportAlert`, `store.go:192-230`:

- `store.go:22` - the single `sync.RWMutex` that guards every map in the store.
- `store.go:195-196` - `s.mu.Lock()` with `defer s.mu.Unlock()`. This is a
  write lock taken *before* the duplicate check and held until the function
  returns, so the "look for a duplicate, then decide" sequence is one atomic
  step. The second request cannot start its lookup until the first has finished
  writing.
- `store.go:202-207` - the duplicate check. If `openAlerts[key]` already points
  at an open alert, this request increments `Count` and updates `LastSeen` and
  returns `created = false`, which the handler turns into 200.
- `store.go:212-229` - the only place an alert is ever created. It runs under
  the same lock and immediately registers the new alert in `openAlerts`
  (`store.go:228`), so by the time the next request acquires the lock, it sees
  the alert and takes the increment path instead.

The important part is that the check and the write are inside the *same*
critical section. If I had used `RLock` to look and then `Lock` to write, two
requests could both read "nothing there" during the read phase and both create
an alert. With 50 concurrent reports, exactly one request gets 201 and the
other 49 get 200, ending at one alert with count 50 -
`TestFiftyConcurrentIdenticalAlerts` asserts exactly that, and
`go test -race` confirms there is no data race.

Two smaller details that keep this safe: the store returns *copies* of structs
(`return *existing`, `store.go:206`), so handlers never read store-owned memory
outside the lock; and the ID counter `s.alertSeq` is incremented under the same
lock (`store.go:212`), so two alerts can never get the same id.

**2. Why does a user from another company get 404 and not 403?**

403 means "you are allowed in, but not allowed to do *this*" - and answering
403 would confirm that the alert exists. A Beta admin could then walk ids
(`alr_1`, `alr_2`, ...) and learn how many alerts Acme has and when they were
created, just from which ids answer 403 and which answer 404. That is an
information leak between customers, even though no alert data is returned.

404 means "there is nothing here for you". It makes "this alert belongs to
someone else" and "this alert does not exist" indistinguishable, so a company
cannot discover anything about another company's data. That is rule R6, and
it is the usual way multi-tenant APIs scope resources.

In the code, the company check lives in the store and produces `ErrNotFound`,
not a permission error: `store.go:268` in `GetAlert` and `store.go:240` in
`ResolveAlert` both use `if !ok || alert.OrgID != orgID { return ErrNotFound }`,
so a missing id and someone else's id take the same path. The handlers then
map that to 404 (`handlers.go:233` and `handlers.go:254`).

Note the ordering this gives on `POST /alerts/{id}/resolve`: a *viewer* from
Acme gets 403, because the role check (`handlers.go:247`) runs before the
lookup and the role is wrong whatever the id is. A Beta *admin* passes the role
check and then gets 404. Those are self-check steps 16 and 17, and both are
covered by tests.
