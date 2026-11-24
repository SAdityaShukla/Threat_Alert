package main

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Errors the store returns so handlers can map them to status codes.
var (
	ErrNotFound        = errors.New("not found")
	ErrAlreadyResolved = errors.New("alert is already resolved")
)

// Store holds every entity in memory. One RWMutex guards all of the maps:
// reads take RLock, anything that changes state takes Lock. The alert
// report path takes the write lock for the whole "look for a duplicate,
// then either increment or create" sequence, which is what makes R8 hold.
type Store struct {
	mu sync.RWMutex

	companies    map[string]*Company
	users        map[string]*User
	usersByToken map[string]*User
	apps         map[string]*App
	appsByKey    map[string]*App
	alerts       map[string]*Alert

	// openAlerts maps (app, device, threat) -> id of the OPEN alert for it.
	// Resolving an alert removes its entry, so the next report of the same
	// threat creates a fresh alert instead of reopening the old one.
	openAlerts map[dedupeKey]string

	orgSeq   int
	userSeq  int
	appSeq   int
	alertSeq int
}

func NewStore() *Store {
	return &Store{
		companies:    make(map[string]*Company),
		users:        make(map[string]*User),
		usersByToken: make(map[string]*User),
		apps:         make(map[string]*App),
		appsByKey:    make(map[string]*App),
		alerts:       make(map[string]*Alert),
		openAlerts:   make(map[dedupeKey]string),
	}
}

// ---------- lookups used by authentication ----------

// UserByToken returns a copy of the user holding this bearer token.
// A copy is returned so callers can never read store-owned memory
// without the lock, which keeps `go test -race` clean.
func (s *Store) UserByToken(token string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.usersByToken[token]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// AppByKey returns a copy of the app owning this appKey.
func (s *Store) AppByKey(key string) (App, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.appsByKey[key]
	if !ok {
		return App{}, false
	}
	return *a, true
}

// ---------- writes ----------

// Register creates a company together with its first user, who is an admin.
// Both are created under one lock so a company can never exist without
// its admin.
func (s *Store) Register(orgName, name, email string) (User, error) {
	token, err := randomHex(tokenBytes)
	if err != nil {
		return User{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.orgSeq++
	company := &Company{
		ID:   fmt.Sprintf("org_%d", s.orgSeq),
		Name: orgName,
	}
	s.companies[company.ID] = company

	user, err := s.createUserLocked(company.ID, name, email, RoleAdmin, token)
	if err != nil {
		return User{}, err
	}
	return *user, nil
}

// CreateUser adds a user to an existing company.
func (s *Store) CreateUser(orgID, name, email, role string) (User, error) {
	token, err := randomHex(tokenBytes)
	if err != nil {
		return User{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, err := s.createUserLocked(orgID, name, email, role, token)
	if err != nil {
		return User{}, err
	}
	return *user, nil
}

// createUserLocked must be called with the write lock held.
func (s *Store) createUserLocked(orgID, name, email, role, token string) (*User, error) {
	// A hex token from 16 random bytes colliding is effectively impossible,
	// but a loop costs nothing and makes the guarantee unconditional.
	for _, taken := s.usersByToken[token]; taken; _, taken = s.usersByToken[token] {
		fresh, err := randomHex(tokenBytes)
		if err != nil {
			return nil, err
		}
		token = fresh
	}

	s.userSeq++
	user := &User{
		ID:    fmt.Sprintf("usr_%d", s.userSeq),
		OrgID: orgID,
		Name:  name,
		Email: email,
		Role:  role,
		Token: token,
	}
	s.users[user.ID] = user
	s.usersByToken[user.Token] = user
	return user, nil
}

// CreateApp adds an app to a company and gives it a random appKey.
func (s *Store) CreateApp(orgID, name, platform string) (App, error) {
	key, err := randomHex(appKeyBytes)
	if err != nil {
		return App{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, taken := s.appsByKey[key]; taken; _, taken = s.appsByKey[key] {
		fresh, err := randomHex(appKeyBytes)
		if err != nil {
			return App{}, err
		}
		key = fresh
	}

	s.appSeq++
	app := &App{
		ID:       fmt.Sprintf("app_%d", s.appSeq),
		OrgID:    orgID,
		Name:     name,
		Platform: platform,
		AppKey:   key,
	}
	s.apps[app.ID] = app
	s.appsByKey[app.AppKey] = app
	return *app, nil
}

// ReportAlert is the repeat-alert logic required by the paper.
//
// It returns the resulting alert and created=true when a brand new alert
// was stored (caller answers 201), created=false when an existing open
// alert was incremented (caller answers 200).
//
// The whole decision runs under one write lock, so two simultaneous
// reports of the same threat can never both decide "nothing exists yet".
func (s *Store) ReportAlert(app App, deviceID, threatType string, severity int) (Alert, bool) {
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	key := dedupeKey{AppID: app.ID, DeviceID: deviceID, ThreatType: threatType}

	// Repeat of an alert that is still open: bump count and lastSeen only.
	// Severity, firstSeen and the id stay as they were.
	if id, ok := s.openAlerts[key]; ok {
		if existing, ok := s.alerts[id]; ok && existing.Status == StatusOpen {
			existing.Count++
			existing.LastSeen = RFC3339Time{now}
			return *existing, false
		}
		// Index entry pointing at something no longer open: drop it.
		delete(s.openAlerts, key)
	}

	s.alertSeq++
	alert := &Alert{
		ID:         fmt.Sprintf("alr_%d", s.alertSeq),
		AppID:      app.ID,
		OrgID:      app.OrgID,
		DeviceID:   deviceID,
		ThreatType: threatType,
		Severity:   severity,
		Count:      1,
		Status:     StatusOpen,
		FirstSeen:  RFC3339Time{now},
		LastSeen:   RFC3339Time{now},
		ResolvedBy: "",
		seq:        s.alertSeq,
	}
	s.alerts[alert.ID] = alert
	s.openAlerts[key] = alert.ID
	return *alert, true
}

// ResolveAlert marks one alert resolved on behalf of an admin.
// Company isolation (R6) is enforced here: an alert from another company
// is reported as ErrNotFound, never as a permission problem.
func (s *Store) ResolveAlert(orgID, alertID, userID string) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[alertID]
	if !ok || alert.OrgID != orgID {
		return Alert{}, ErrNotFound
	}
	if alert.Status == StatusResolved {
		return Alert{}, ErrAlreadyResolved
	}

	alert.Status = StatusResolved
	alert.ResolvedBy = userID

	// The alert is no longer a candidate for repeat counting, so the next
	// report of the same threat starts a new alert with count 1.
	delete(s.openAlerts, dedupeKey{
		AppID:      alert.AppID,
		DeviceID:   alert.DeviceID,
		ThreatType: alert.ThreatType,
	})
	return *alert, nil
}

// ---------- reads ----------

// GetAlert returns one alert belonging to orgID. Anything else is not found.
func (s *Store) GetAlert(orgID, alertID string) (Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alert, ok := s.alerts[alertID]
	if !ok || alert.OrgID != orgID {
		return Alert{}, ErrNotFound
	}
	return *alert, nil
}

// ListAlerts returns the company's alerts, newest lastSeen first.
// status is "", "open" or "resolved". The slice is always non-nil so the
// JSON is [] and never null.
func (s *Store) ListAlerts(orgID, status string) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		if alert.OrgID != orgID {
			continue
		}
		if status != "" && alert.Status != status {
			continue
		}
		out = append(out, *alert)
	}

	// Newest lastSeen first. Timestamps have nanosecond precision in memory,
	// but two alerts can still share one; creation order breaks the tie so
	// the ordering is stable instead of map-random.
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen.Time) {
			return out[i].seq > out[j].seq
		}
		return out[i].LastSeen.After(out[j].LastSeen.Time)
	})
	return out
}

// SummaryBySeverity counts a company's open alerts per severity (bonus
// endpoint GET /summary). Every severity 1-5 is present, so the caller
// always gets the same shape.
func (s *Store) SummaryBySeverity(orgID string) map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := map[string]int{"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
	for _, alert := range s.alerts {
		if alert.OrgID != orgID || alert.Status != StatusOpen {
			continue
		}
		counts[fmt.Sprintf("%d", alert.Severity)]++
	}
	return counts
}
