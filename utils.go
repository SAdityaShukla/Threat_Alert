package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	// R7: at least 16 random bytes, hex encoded (so 32 hex characters).
	tokenBytes  = 16
	appKeyBytes = 16

	// A threat report is a few hundred bytes; refuse anything absurd rather
	// than reading an unbounded body into memory.
	maxBodyBytes = 1 << 20 // 1 MiB
)

// randomHex returns n cryptographically random bytes as a hex string.
// crypto/rand is used, never math/rand, so tokens and app keys cannot be
// predicted from each other or from the time they were made.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// writeJSON sends any value as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		// Encoding our own structs cannot realistically fail; if it ever
		// does, still answer with JSON rather than an empty body.
		log.Printf("json encode failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError sends {"error": "..."} with a status code (R4).
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// jsonErrors wraps a handler so that the two error responses Go writes by
// itself - "404 page not found" for an unknown path and "405 method not
// allowed" for a wrong method - come back as JSON too, which is what R4
// asks for. The status code and the Allow header Go sets are untouched.
func jsonErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&jsonErrorWriter{ResponseWriter: w}, r)
	})
}

type jsonErrorWriter struct {
	http.ResponseWriter
	replaced bool
}

func (w *jsonErrorWriter) WriteHeader(status int) {
	// Our own handlers always set a JSON content type before writing the
	// header, so only Go's plain-text defaults reach the branch below.
	isDefaultError := status == http.StatusNotFound || status == http.StatusMethodNotAllowed
	if !isDefaultError || w.Header().Get("Content-Type") == "application/json" {
		w.ResponseWriter.WriteHeader(status)
		return
	}

	message := "not found"
	if status == http.StatusMethodNotAllowed {
		message = "method not allowed"
	}

	w.replaced = true
	w.Header().Set("Content-Type", "application/json")
	w.ResponseWriter.WriteHeader(status)
	_, _ = w.ResponseWriter.Write([]byte(`{"error":"` + message + `"}`))
}

// Write drops the plain-text body that Go was about to send, because the
// JSON replacement has already been written.
func (w *jsonErrorWriter) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// decodeJSONBody reads the request body into dst. Any malformed body is a
// 400 as far as the caller is concerned, so a single bool is enough.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "body must be valid JSON")
		return false
	}
	return true
}

// nonEmpty reports whether a field has real content, not just spaces.
func nonEmpty(value string) bool {
	return strings.TrimSpace(value) != ""
}

// validEmail applies the paper's rule: the address must contain "@".
func validEmail(email string) bool {
	return strings.Contains(email, "@")
}

// validRole and validPlatform guard the two closed sets of values.
func validRole(role string) bool {
	return role == RoleAdmin || role == RoleViewer
}

func validPlatform(platform string) bool {
	return platform == PlatformAndroid || platform == PlatformIOS
}

// validSeverity: a whole number from 1 to 5. The handler decodes severity
// into *int, so a missing value or a fraction like 4.5 never reaches here.
func validSeverity(severity int) bool {
	return severity >= 1 && severity <= 5
}
