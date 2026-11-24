package main

import (
	"net/http"
	"strings"
)

// bearerToken pulls the token out of "Authorization: Bearer <token>".
// The scheme name is matched case-insensitively because HTTP auth schemes
// are case-insensitive; the token itself is compared exactly.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// authenticateUser is step 1 of R5 for every user-facing route.
// On failure it has already written a 401 and the handler must return.
func (s *Server) authenticateUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return User{}, false
	}

	user, ok := s.store.UserByToken(token)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return User{}, false
	}
	return user, true
}

// requireAdmin is step 2 of R5. The caller is known at this point, so a
// failure here is 403 and never 401.
func requireAdmin(w http.ResponseWriter, user User) bool {
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return false
	}
	return true
}

// authenticateApp is the SDK's authentication: "X-App-Key: <appKey>".
// A wrong or missing key is 401, exactly like a wrong user token.
func (s *Server) authenticateApp(w http.ResponseWriter, r *http.Request) (App, bool) {
	key := strings.TrimSpace(r.Header.Get("X-App-Key"))
	if key == "" {
		writeError(w, http.StatusUnauthorized, "missing app key")
		return App{}, false
	}

	app, ok := s.store.AppByKey(key)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid app key")
		return App{}, false
	}
	return app, true
}
