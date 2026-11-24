package main

import "time"

// Role and status values used across the API. Keeping them as named
// constants stops typos like "Admin" or "Resolved" from slipping in.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	PlatformAndroid = "android"
	PlatformIOS     = "ios"

	StatusOpen     = "open"
	StatusResolved = "resolved"
)

// RFC3339Time wraps time.Time so that JSON output is always UTC with
// second precision, exactly like the paper's example "2026-11-23T10:00:00Z".
// time.Time's own marshaller would print nanoseconds. The full-precision
// value is still kept in memory, which is what sorting uses.
type RFC3339Time struct {
	time.Time
}

func (t RFC3339Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Format(time.RFC3339) + `"`), nil
}

func (t *RFC3339Time) UnmarshalJSON(b []byte) error {
	// Only needed so tests can decode an alert back into this struct.
	parsed, err := time.Parse(`"`+time.RFC3339+`"`, string(b))
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// Company is one customer organisation, created by POST /register.
type Company struct {
	ID   string `json:"orgId"`
	Name string `json:"orgName"`
}

// User belongs to exactly one company and authenticates with Token.
type User struct {
	ID    string `json:"userId"`
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Token string `json:"token"`
}

// IsAdmin keeps the role comparison in one place.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// App belongs to one company. The SDK authenticates with AppKey.
// OrgID is hidden from JSON because the paper fixes the app response to
// exactly appId, name, platform and appKey.
type App struct {
	ID       string `json:"appId"`
	OrgID    string `json:"-"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	AppKey   string `json:"appKey"`
}

// Alert is one threat found on one device through one app.
// OrgID is denormalised from the app so company checks need no second lookup;
// seq is the creation order, used only to break ties when sorting.
type Alert struct {
	ID         string      `json:"id"`
	AppID      string      `json:"appId"`
	OrgID      string      `json:"-"`
	DeviceID   string      `json:"deviceId"`
	ThreatType string      `json:"threatType"`
	Severity   int         `json:"severity"`
	Count      int         `json:"count"`
	Status     string      `json:"status"`
	FirstSeen  RFC3339Time `json:"firstSeen"`
	LastSeen   RFC3339Time `json:"lastSeen"`
	ResolvedBy string      `json:"resolvedBy"`

	seq int
}

// dedupeKey identifies the "same alert" for repeat handling: same app,
// same device, same threat type. Only open alerts are kept in that index.
type dedupeKey struct {
	AppID      string
	DeviceID   string
	ThreatType string
}
