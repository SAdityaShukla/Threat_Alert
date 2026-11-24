package main

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// Server bundles the handlers with the one store they share.
type Server struct {
	store *Store
}

func NewServer(store *Store) *Server {
	return &Server{store: store}
}

// Handler is what the server actually serves: the routes plus the small
// wrapper that turns Go's own 404 and 405 bodies into JSON.
func (s *Server) Handler() http.Handler {
	return jsonErrors(s.Routes())
}

// Routes registers every route on a Go 1.22+ method-aware ServeMux.
// Because each pattern names its method, a request with the wrong method
// gets Go's own 405 response for free (R4).
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("POST /users", s.handleCreateUser)
	mux.HandleFunc("POST /apps", s.handleCreateApp)
	mux.HandleFunc("POST /alerts", s.handleReportAlert)
	mux.HandleFunc("GET /alerts", s.handleListAlerts)
	mux.HandleFunc("GET /alerts/{id}", s.handleGetAlert)
	mux.HandleFunc("POST /alerts/{id}/resolve", s.handleResolveAlert)

	// Bonus endpoint, additive and outside the paper's required routes.
	mux.HandleFunc("GET /summary", s.handleSummary)

	return mux
}

// POST /register - public. Creates a company plus its first admin user.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName string `json:"orgName"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	// No authentication step here, so input validation is the first check.
	if !nonEmpty(req.OrgName) {
		writeError(w, http.StatusBadRequest, "orgName is required")
		return
	}
	if !nonEmpty(req.Name) {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "email must contain @")
		return
	}

	user, err := s.store.Register(req.OrgName, req.Name, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create company")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// POST /users - admin only. Adds a user to the caller's own company.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	// R5: who is calling (401), then their role (403), then the input (400).
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}
	if !requireAdmin(w, caller) {
		return
	}

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if !nonEmpty(req.Name) {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "email must contain @")
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, `role must be "admin" or "viewer"`)
		return
	}

	// The company is taken from the caller's token, never from the body,
	// so nobody can add a user to another company (R6).
	user, err := s.store.CreateUser(caller.OrgID, req.Name, req.Email, req.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// POST /apps - admin only. Adds an app to the caller's own company.
func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}
	if !requireAdmin(w, caller) {
		return
	}

	var req struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if !nonEmpty(req.Name) {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validPlatform(req.Platform) {
		writeError(w, http.StatusBadRequest, `platform must be "android" or "ios"`)
		return
	}

	app, err := s.store.CreateApp(caller.OrgID, req.Name, req.Platform)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create app")
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

// POST /alerts - SDK only, authenticated with the app key.
// 201 for a new alert, 200 when an existing open alert was counted up.
func (s *Server) handleReportAlert(w http.ResponseWriter, r *http.Request) {
	app, ok := s.authenticateApp(w, r)
	if !ok {
		return
	}

	var req struct {
		DeviceID   string `json:"deviceId"`
		ThreatType string `json:"threatType"`
		// Decoded as a float so that a fraction such as 4.5 can be
		// rejected with a clear message instead of a decoding error,
		// and a missing field can be told apart from a zero.
		Severity *float64 `json:"severity"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if !nonEmpty(req.DeviceID) {
		writeError(w, http.StatusBadRequest, "deviceId is required")
		return
	}
	if !nonEmpty(req.ThreatType) {
		writeError(w, http.StatusBadRequest, "threatType is required")
		return
	}
	if req.Severity == nil || *req.Severity != math.Trunc(*req.Severity) ||
		!validSeverity(int(*req.Severity)) {
		writeError(w, http.StatusBadRequest, "severity must be a whole number from 1 to 5")
		return
	}

	alert, created := s.store.ReportAlert(app, req.DeviceID, req.ThreatType, int(*req.Severity))
	if created {
		writeJSON(w, http.StatusCreated, alert)
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

// GET /alerts - admin or viewer. Only the caller's own company.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}
	// Both roles may read, so there is no role check to fail here.

	status := r.URL.Query().Get("status")
	if status != "" && status != StatusOpen && status != StatusResolved {
		writeError(w, http.StatusBadRequest, `status must be "open" or "resolved"`)
		return
	}

	alerts := s.store.ListAlerts(caller.OrgID, status)

	// Bonus: optional ?limit= and ?offset= paging, applied after sorting.
	alerts, ok = paginate(w, r, alerts)
	if !ok {
		return
	}

	// alerts is always a non-nil slice, so the JSON is [] and never null.
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// GET /alerts/{id} - admin or viewer, own company only.
func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}

	alert, err := s.store.GetAlert(caller.OrgID, r.PathValue("id"))
	if err != nil {
		// Another company's alert and a non-existent alert are reported
		// identically, so no one can probe for ids that are not theirs.
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

// POST /alerts/{id}/resolve - admin only, own company only.
func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}
	// Role is checked before the alert is looked up: a viewer gets 403 even
	// for an alert that does not exist, which is the order R5 asks for.
	if !requireAdmin(w, caller) {
		return
	}

	alert, err := s.store.ResolveAlert(caller.OrgID, r.PathValue("id"), caller.ID)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "alert not found")
	case errors.Is(err, ErrAlreadyResolved):
		writeError(w, http.StatusConflict, "alert is already resolved")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not resolve alert")
	default:
		writeJSON(w, http.StatusOK, alert)
	}
}

// GET /summary - bonus. Open alerts per severity for the caller's company.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticateUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"openBySeverity": s.store.SummaryBySeverity(caller.OrgID),
	})
}

// paginate applies the optional ?limit= and ?offset= query parameters.
// Absent parameters mean "everything", which is what the paper's own
// self-check steps rely on.
func paginate(w http.ResponseWriter, r *http.Request, alerts []Alert) ([]Alert, bool) {
	query := r.URL.Query()

	offset := 0
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a number of 0 or more")
			return nil, false
		}
		offset = parsed
	}

	limit := len(alerts)
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a number of 1 or more")
			return nil, false
		}
		limit = parsed
	}

	if offset >= len(alerts) {
		return []Alert{}, true
	}
	end := offset + limit
	if end > len(alerts) {
		end = len(alerts)
	}
	return alerts[offset:end], true
}
