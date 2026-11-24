package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------- helpers ----------

// newTestHandler gives every test its own empty store, so tests never
// affect each other and can run in any order.
func newTestHandler() http.Handler {
	return NewServer(NewStore()).Handler()
}

// do sends one request straight to the handler with httptest, so no real
// TCP port is needed.
func do(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func appKey(key string) map[string]string {
	return map[string]string{"X-App-Key": key}
}

func decodeInto(t *testing.T, recorder *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), dst); err != nil {
		t.Fatalf("decoding response %q: %v", recorder.Body.String(), err)
	}
}

// registerCompany creates a company and returns its first admin.
func registerCompany(t *testing.T, handler http.Handler, orgName, name, email string) User {
	t.Helper()

	body := fmt.Sprintf(`{"orgName":%q,"name":%q,"email":%q}`, orgName, name, email)
	recorder := do(t, handler, http.MethodPost, "/register", body, nil)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register %s: got status %d, want 201", orgName, recorder.Code)
	}

	var user User
	decodeInto(t, recorder, &user)
	return user
}

func addUser(t *testing.T, handler http.Handler, adminToken, name, email, role string) User {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"email":%q,"role":%q}`, name, email, role)
	recorder := do(t, handler, http.MethodPost, "/users", body, bearer(adminToken))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("add user %s: got status %d, want 201", name, recorder.Code)
	}

	var user User
	decodeInto(t, recorder, &user)
	return user
}

func addApp(t *testing.T, handler http.Handler, adminToken, name, platform string) App {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"platform":%q}`, name, platform)
	recorder := do(t, handler, http.MethodPost, "/apps", body, bearer(adminToken))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("add app %s: got status %d, want 201", name, recorder.Code)
	}

	var app App
	decodeInto(t, recorder, &app)
	return app
}

func reportAlert(t *testing.T, handler http.Handler, key, deviceID, threatType string, severity int) (Alert, int) {
	t.Helper()

	body := fmt.Sprintf(`{"deviceId":%q,"threatType":%q,"severity":%d}`, deviceID, threatType, severity)
	recorder := do(t, handler, http.MethodPost, "/alerts", body, appKey(key))

	var alert Alert
	if recorder.Code == http.StatusCreated || recorder.Code == http.StatusOK {
		decodeInto(t, recorder, &alert)
	}
	return alert, recorder.Code
}

func listAlerts(t *testing.T, handler http.Handler, token, query string) []Alert {
	t.Helper()

	recorder := do(t, handler, http.MethodGet, "/alerts"+query, "", bearer(token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list alerts: got status %d, want 200", recorder.Code)
	}

	var payload struct {
		Alerts []Alert `json:"alerts"`
	}
	decodeInto(t, recorder, &payload)
	return payload.Alerts
}

// ---------- required test 1: a viewer gets 403 when resolving ----------

func TestViewerResolvingAlertGets403(t *testing.T) {
	handler := newTestHandler()

	admin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	viewer := addUser(t, handler, admin.Token, "Vik", "vik@acme.test", RoleViewer)
	app := addApp(t, handler, admin.Token, "Acme Pay", PlatformAndroid)

	alert, status := reportAlert(t, handler, app.AppKey, "d1", "ROOT_DETECTED", 5)
	if status != http.StatusCreated {
		t.Fatalf("first report: got status %d, want 201", status)
	}

	recorder := do(t, handler, http.MethodPost, "/alerts/"+alert.ID+"/resolve", "", bearer(viewer.Token))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer resolving: got status %d, want 403", recorder.Code)
	}

	// The alert must be untouched after the refused attempt.
	after := do(t, handler, http.MethodGet, "/alerts/"+alert.ID, "", bearer(admin.Token))
	var reloaded Alert
	decodeInto(t, after, &reloaded)
	if reloaded.Status != StatusOpen {
		t.Fatalf("alert status after refused resolve: got %q, want %q", reloaded.Status, StatusOpen)
	}
	if reloaded.ResolvedBy != "" {
		t.Fatalf("resolvedBy after refused resolve: got %q, want empty", reloaded.ResolvedBy)
	}
}

// ---------- required test 2: another company gets 404 ----------

func TestUserFromOtherCompanyGets404ForAlert(t *testing.T) {
	handler := newTestHandler()

	acmeAdmin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	betaAdmin := registerCompany(t, handler, "Beta", "Ravi", "ravi@beta.test")
	acmeApp := addApp(t, handler, acmeAdmin.Token, "Acme Pay", PlatformAndroid)

	alert, status := reportAlert(t, handler, acmeApp.AppKey, "d1", "ROOT_DETECTED", 5)
	if status != http.StatusCreated {
		t.Fatalf("first report: got status %d, want 201", status)
	}

	// Reading another company's alert: 404, not 403, so Beta cannot even
	// learn that this id exists.
	recorder := do(t, handler, http.MethodGet, "/alerts/"+alert.ID, "", bearer(betaAdmin.Token))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("other company reading alert: got status %d, want 404", recorder.Code)
	}

	// Beta's admin passes the role check, so resolving must also be a 404.
	recorder = do(t, handler, http.MethodPost, "/alerts/"+alert.ID+"/resolve", "", bearer(betaAdmin.Token))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("other company resolving alert: got status %d, want 404", recorder.Code)
	}

	// Beta's own list stays empty, and it is [] rather than null.
	if got := listAlerts(t, handler, betaAdmin.Token, ""); len(got) != 0 {
		t.Fatalf("beta alert list: got %d alerts, want 0", len(got))
	}
	body := do(t, handler, http.MethodGet, "/alerts", "", bearer(betaAdmin.Token)).Body.String()
	if !strings.Contains(body, `"alerts":[]`) {
		t.Fatalf("empty list body: got %s, want an empty array", body)
	}
}

// ---------- required test 3: 50 identical alerts at once ----------

func TestFiftyConcurrentIdenticalAlerts(t *testing.T) {
	handler := newTestHandler()

	admin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	app := addApp(t, handler, admin.Token, "Acme Pay", PlatformAndroid)

	const reports = 50
	body := `{"deviceId":"d2","threatType":"FRIDA_DETECTED","severity":4}`

	// All 50 goroutines wait on the same channel so they start together
	// and really do contend for the store's lock.
	start := make(chan struct{})
	statuses := make([]int, reports)

	var wg sync.WaitGroup
	for i := 0; i < reports; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start

			req := httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(body))
			req.Header.Set("X-App-Key", app.AppKey)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			statuses[index] = recorder.Code
		}(i)
	}
	close(start)
	wg.Wait()

	// Exactly one request may create the alert; the other 49 must update it.
	created := 0
	for index, status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusOK:
		default:
			t.Fatalf("report %d: got status %d, want 200 or 201", index, status)
		}
	}
	if created != 1 {
		t.Fatalf("requests answering 201: got %d, want exactly 1", created)
	}

	alerts := listAlerts(t, handler, admin.Token, "?status=open")
	if len(alerts) != 1 {
		t.Fatalf("open alerts: got %d, want 1", len(alerts))
	}
	if alerts[0].Count != reports {
		t.Fatalf("alert count: got %d, want %d", alerts[0].Count, reports)
	}
	if alerts[0].DeviceID != "d2" || alerts[0].ThreatType != "FRIDA_DETECTED" {
		t.Fatalf("unexpected alert: %+v", alerts[0])
	}
}

// ---------- extra tests for the rules that are easy to get wrong ----------

// Repeat handling, resolving, 409 and "a resolved threat starts a new alert"
// are self-check steps 9, 10, 18, 19 and 20.
func TestRepeatResolveThenNewAlert(t *testing.T) {
	handler := newTestHandler()

	admin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	app := addApp(t, handler, admin.Token, "Acme Pay", PlatformAndroid)

	first, status := reportAlert(t, handler, app.AppKey, "d1", "ROOT_DETECTED", 5)
	if status != http.StatusCreated || first.Count != 1 || first.Status != StatusOpen {
		t.Fatalf("first report: status %d, alert %+v", status, first)
	}

	repeat, status := reportAlert(t, handler, app.AppKey, "d1", "ROOT_DETECTED", 3)
	if status != http.StatusOK {
		t.Fatalf("repeat report: got status %d, want 200", status)
	}
	if repeat.ID != first.ID {
		t.Fatalf("repeat id: got %q, want %q", repeat.ID, first.ID)
	}
	if repeat.Count != 2 {
		t.Fatalf("repeat count: got %d, want 2", repeat.Count)
	}
	if repeat.Severity != first.Severity {
		t.Fatalf("severity changed on repeat: got %d, want %d", repeat.Severity, first.Severity)
	}
	if !repeat.FirstSeen.Equal(first.FirstSeen.Time) {
		t.Fatalf("firstSeen changed on repeat: got %v, want %v", repeat.FirstSeen, first.FirstSeen)
	}

	recorder := do(t, handler, http.MethodPost, "/alerts/"+first.ID+"/resolve", "", bearer(admin.Token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin resolving: got status %d, want 200", recorder.Code)
	}
	var resolved Alert
	decodeInto(t, recorder, &resolved)
	if resolved.Status != StatusResolved {
		t.Fatalf("status after resolve: got %q, want %q", resolved.Status, StatusResolved)
	}
	if resolved.ResolvedBy != admin.ID {
		t.Fatalf("resolvedBy: got %q, want %q", resolved.ResolvedBy, admin.ID)
	}

	recorder = do(t, handler, http.MethodPost, "/alerts/"+first.ID+"/resolve", "", bearer(admin.Token))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("second resolve: got status %d, want 409", recorder.Code)
	}

	// Same threat after it was resolved: a brand new alert with count 1.
	again, status := reportAlert(t, handler, app.AppKey, "d1", "ROOT_DETECTED", 5)
	if status != http.StatusCreated {
		t.Fatalf("report after resolve: got status %d, want 201", status)
	}
	if again.ID == first.ID {
		t.Fatalf("report after resolve reused id %q", again.ID)
	}
	if again.Count != 1 {
		t.Fatalf("new alert count: got %d, want 1", again.Count)
	}

	if open := listAlerts(t, handler, admin.Token, "?status=open"); len(open) != 1 {
		t.Fatalf("open alerts: got %d, want 1", len(open))
	}
	if done := listAlerts(t, handler, admin.Token, "?status=resolved"); len(done) != 1 {
		t.Fatalf("resolved alerts: got %d, want 1", len(done))
	}
}

// R5 asks for authentication, then role, then input, then existence.
func TestCheckOrderAndBadInput(t *testing.T) {
	handler := newTestHandler()

	admin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	viewer := addUser(t, handler, admin.Token, "Vik", "vik@acme.test", RoleViewer)

	cases := []struct {
		name    string
		method  string
		path    string
		body    string
		headers map[string]string
		want    int
	}{
		{"no token", http.MethodPost, "/users", `{"name":"Xia","email":"xia@acme.test","role":"admin"}`, nil, http.StatusUnauthorized},
		{"wrong token", http.MethodPost, "/users", `{"name":"Xia","email":"xia@acme.test","role":"admin"}`, bearer("nope"), http.StatusUnauthorized},
		// A viewer sending an invalid body still gets 403: role before input.
		{"viewer before input", http.MethodPost, "/users", `{"name":"","email":"bad","role":"wizard"}`, bearer(viewer.Token), http.StatusForbidden},
		{"bad email", http.MethodPost, "/register", `{"orgName":"Gamma","name":"Gita","email":"not-an-email"}`, nil, http.StatusBadRequest},
		{"bad role", http.MethodPost, "/users", `{"name":"Xia","email":"xia@acme.test","role":"wizard"}`, bearer(admin.Token), http.StatusBadRequest},
		{"bad platform", http.MethodPost, "/apps", `{"name":"Acme Web","platform":"windows"}`, bearer(admin.Token), http.StatusBadRequest},
		{"broken json", http.MethodPost, "/register", `{"orgName":`, nil, http.StatusBadRequest},
		{"bad status filter", http.MethodGet, "/alerts?status=everything", "", bearer(admin.Token), http.StatusBadRequest},
		{"missing alert", http.MethodGet, "/alerts/alr_999", "", bearer(admin.Token), http.StatusNotFound},
		{"missing app key", http.MethodPost, "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`, nil, http.StatusUnauthorized},
		{"wrong app key", http.MethodPost, "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`, appKey("wrong-key"), http.StatusUnauthorized},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := do(t, handler, testCase.method, testCase.path, testCase.body, testCase.headers)
			if recorder.Code != testCase.want {
				t.Fatalf("got status %d, want %d (body %s)", recorder.Code, testCase.want, recorder.Body.String())
			}
			// Every failure must be JSON shaped like {"error": "..."}.
			var payload struct {
				Error string `json:"error"`
			}
			decodeInto(t, recorder, &payload)
			if payload.Error == "" {
				t.Fatalf("error body has no message: %s", recorder.Body.String())
			}
		})
	}
}

// Severity must be a whole number from 1 to 5.
func TestSeverityValidation(t *testing.T) {
	handler := newTestHandler()

	admin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	app := addApp(t, handler, admin.Token, "Acme Pay", PlatformAndroid)

	bad := []string{
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":9}`,
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":0}`,
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":-1}`,
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":4.5}`,
		`{"deviceId":"d1","threatType":"ROOT_DETECTED"}`,
		`{"deviceId":"","threatType":"ROOT_DETECTED","severity":5}`,
		`{"deviceId":"d1","threatType":"","severity":5}`,
	}
	for _, body := range bad {
		recorder := do(t, handler, http.MethodPost, "/alerts", body, appKey(app.AppKey))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %s: got status %d, want 400", body, recorder.Code)
		}
	}

	for severity := 1; severity <= 5; severity++ {
		device := fmt.Sprintf("device-%d", severity)
		if _, status := reportAlert(t, handler, app.AppKey, device, "ROOT_DETECTED", severity); status != http.StatusCreated {
			t.Fatalf("severity %d: got status %d, want 201", severity, status)
		}
	}
}

// Tokens and app keys must be random hex of at least 16 bytes (R7).
func TestCredentialsAreRandomHex(t *testing.T) {
	handler := newTestHandler()

	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		admin := registerCompany(t, handler, fmt.Sprintf("Org%d", i), "Asha", "asha@acme.test")
		app := addApp(t, handler, admin.Token, "App", PlatformAndroid)

		for _, credential := range []string{admin.Token, app.AppKey} {
			if len(credential) < 2*tokenBytes {
				t.Fatalf("credential %q is only %d hex characters, want at least %d", credential, len(credential), 2*tokenBytes)
			}
			if strings.Trim(credential, "0123456789abcdef") != "" {
				t.Fatalf("credential %q is not hex", credential)
			}
			if seen[credential] {
				t.Fatalf("credential %q was handed out twice", credential)
			}
			seen[credential] = true
		}
	}
}

// Go's own 404 and 405 replies must also be JSON (R4).
func TestDefaultErrorsAreJSON(t *testing.T) {
	handler := newTestHandler()

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound},
		{"wrong method on /alerts/{id}", http.MethodDelete, "/alerts/alr_1", http.StatusMethodNotAllowed},
		{"wrong method on /register", http.MethodGet, "/register", http.StatusMethodNotAllowed},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := do(t, handler, testCase.method, testCase.path, "", nil)
			if recorder.Code != testCase.want {
				t.Fatalf("got status %d, want %d", recorder.Code, testCase.want)
			}
			if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
				t.Fatalf("content type: got %q, want application/json", contentType)
			}
			var payload struct {
				Error string `json:"error"`
			}
			decodeInto(t, recorder, &payload)
			if payload.Error == "" {
				t.Fatalf("error body has no message: %s", recorder.Body.String())
			}
		})
	}
}

// Newest lastSeen first, and alerts of other companies never appear.
func TestListOrderAndIsolation(t *testing.T) {
	handler := newTestHandler()

	acmeAdmin := registerCompany(t, handler, "Acme", "Asha", "asha@acme.test")
	betaAdmin := registerCompany(t, handler, "Beta", "Ravi", "ravi@beta.test")
	acmeApp := addApp(t, handler, acmeAdmin.Token, "Acme Pay", PlatformAndroid)
	betaApp := addApp(t, handler, betaAdmin.Token, "Beta Pay", PlatformIOS)

	first, _ := reportAlert(t, handler, acmeApp.AppKey, "d1", "ROOT_DETECTED", 5)
	second, _ := reportAlert(t, handler, acmeApp.AppKey, "d2", "FRIDA_DETECTED", 4)
	reportAlert(t, handler, betaApp.AppKey, "d9", "ROOT_DETECTED", 2)

	acmeAlerts := listAlerts(t, handler, acmeAdmin.Token, "")
	if len(acmeAlerts) != 2 {
		t.Fatalf("acme alerts: got %d, want 2", len(acmeAlerts))
	}
	if acmeAlerts[0].ID != second.ID || acmeAlerts[1].ID != first.ID {
		t.Fatalf("order: got %s then %s, want %s then %s",
			acmeAlerts[0].ID, acmeAlerts[1].ID, second.ID, first.ID)
	}

	betaAlerts := listAlerts(t, handler, betaAdmin.Token, "")
	if len(betaAlerts) != 1 {
		t.Fatalf("beta alerts: got %d, want 1", len(betaAlerts))
	}
	if betaAlerts[0].DeviceID != "d9" {
		t.Fatalf("beta sees another company's alert: %+v", betaAlerts[0])
	}
}
