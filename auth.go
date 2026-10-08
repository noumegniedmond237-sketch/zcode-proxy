package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---- Authentification de l'interface Web ----
// /api/* utilise une authentification par session (sauf /api/login)
// /v1/* utilise une clé API (préfixe sk-)
// La page /web et le callback /oauth/callback sont toujours accessibles

const (
	sessionCookieName = "zcode_session"
	sessionExpiry     = 24 * time.Hour
)

type sessionEntry struct {
	username  string
	createdAt time.Time
	expiresAt time.Time
}

// AuthManager gestionnaire d'authentification
type AuthManager struct {
	mu          sync.RWMutex
	sessions    map[string]*sessionEntry
	fallbackPwd string
	db          *DB

	failMu   sync.Mutex
	failures map[string]*loginFail // Limitation du débit des échecs : key = ip|user
}

type loginFail struct {
	count       int
	lockedUntil time.Time
}

const (
	loginMaxFails = 5
	loginLockBase = 60 * time.Second
	loginLockMax  = 30 * time.Minute
)

// NewAuthManager crée le gestionnaire d'authentification (admin/admin par défaut, surchargeable via variable d'environnement)
func NewAuthManager(db *DB, password string) *AuthManager {
	if password == "" {
		password = "admin"
	}
	return &AuthManager{
		sessions:    make(map[string]*sessionEntry),
		fallbackPwd: password,
		db:          db,
		failures:    make(map[string]*loginFail),
	}
}

// hashPassword hachage bcrypt (nouveau mot de passe)
func hashPassword(pwd string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("[auth] bcrypt hash failed: %v", err)
	}
	return string(h)
}

// legacyHash ancien SHA-256 sans sel (uniquement pour migration transparente)
func legacyHash(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

// verifyPassword vérifie le mot de passe ; met à niveau vers bcrypt si ancien SHA-256
func (am *AuthManager) verifyPassword(pwd string) bool {
	stored := ""
	if am.db != nil {
		stored, _ = am.db.GetPasswordHash()
	}
	if stored != "" {
		if strings.HasPrefix(stored, "$2") {
			return bcrypt.CompareHashAndPassword([]byte(stored), []byte(pwd)) == nil
		}
		if legacyHash(pwd) == stored {
			am.db.SetPasswordHash(hashPassword(pwd))
			log.Printf("[auth] password hash migrated to bcrypt")
			return true
		}
		return false
	}
	return pwd == am.fallbackPwd
}

// checkLoginRate limitation du débit de connexion : renvoie la durée restante si verrouillé
func (am *AuthManager) checkLoginRate(key string) time.Duration {
	am.failMu.Lock()
	defer am.failMu.Unlock()
	f, ok := am.failures[key]
	if !ok {
		return 0
	}
	if time.Now().Before(f.lockedUntil) {
		return time.Until(f.lockedUntil)
	}
	return 0
}

// recordLoginFail enregistre un échec et verrouille selon un recul exponentiel
func (am *AuthManager) recordLoginFail(key string) {
	am.failMu.Lock()
	defer am.failMu.Unlock()
	f := am.failures[key]
	if f == nil {
		f = &loginFail{}
		am.failures[key] = f
	}
	f.count++
	if f.count >= loginMaxFails {
		backoff := loginLockBase << (uint(f.count/loginMaxFails) - 1)
		if backoff > loginLockMax {
			backoff = loginLockMax
		}
		f.lockedUntil = time.Now().Add(backoff)
		log.Printf("[auth] login locked %s for %v (fails=%d)", key, backoff, f.count)
	}
}

func (am *AuthManager) clearLoginFail(key string) {
	am.failMu.Lock()
	delete(am.failures, key)
	am.failMu.Unlock()
}

func (am *AuthManager) adminUser() string {
	if am.db != nil {
		if u, err := am.db.GetAdminUser(); err == nil && u != "" {
			return u
		}
	}
	return "admin"
}

func (am *AuthManager) isDefaultPassword() bool {
	if am.db != nil {
		isDefault, _ := am.db.IsDefaultPassword()
		return isDefault
	}
	return am.fallbackPwd == "admin"
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[auth] crypto rand failed: %v", err)
	}
	return hex.EncodeToString(b)
}

// GenerateAPIKey génère une clé API avec le préfixe sk-
func GenerateAPIKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[auth] crypto rand failed: %v", err)
	}
	return "sk-" + hex.EncodeToString(b)
}

// Login vérifie les identifiants et crée une session (avec limitation par IP+nom d'utilisateur)
func (am *AuthManager) Login(username, password, clientIP string) (string, bool, time.Duration) {
	rateKey := clientIP + "|" + username
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		return "", false, wait
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	if username != am.adminUser() {
		am.recordLoginFail(rateKey)
		return "", false, 0
	}
	if !am.verifyPassword(password) {
		am.recordLoginFail(rateKey)
		return "", false, 0
	}
	am.clearLoginFail(rateKey)

	now := time.Now()
	for token, s := range am.sessions {
		if now.After(s.expiresAt) {
			delete(am.sessions, token)
		}
	}
	token := generateToken()
	am.sessions[token] = &sessionEntry{username: username, createdAt: now, expiresAt: now.Add(sessionExpiry)}
	log.Printf("[auth] login success: user=%s", username)
	return token, true, 0
}

func (am *AuthManager) Logout(token string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.sessions, token)
}

func (am *AuthManager) IsValid(token string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	s, ok := am.sessions[token]
	if !ok {
		return false
	}
	return !time.Now().After(s.expiresAt)
}

// clientIP extrait l'adresse IP du client
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func extractToken(r *http.Request) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// ValidateAPIKey valide la clé API /v1
func (am *AuthManager) ValidateAPIKey(key string) bool {
	if am.db == nil || key == "" {
		return false
	}
	stored, err := am.db.GetAPIKey()
	if err != nil || stored == "" {
		return false
	}
	// Comparaison en temps constant pour éviter les attaques temporelles
	return subtle.ConstantTimeCompare([]byte(key), []byte(stored)) == 1
}

// Middleware d'authentification
func (am *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Chemins sans authentification : connexion, santé, interface web, callback OAuth
		if path == "/api/login" || path == "/health" ||
			strings.HasPrefix(path, "/web") || strings.HasPrefix(path, "/oauth/") {
			next.ServeHTTP(w, r)
			return
		}

		// /v1/* utilise une clé API (Authorization: Bearer ou x-api-key)
		if strings.HasPrefix(path, "/v1/") {
			var apiKey string
			if xKey := r.Header.Get("x-api-key"); xKey != "" {
				apiKey = xKey
			} else if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
			if apiKey == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"error": map[string]string{
						"message": "API key required. Use 'Authorization: Bearer <key>' or 'x-api-key: <key>'",
						"type":    "authentication_error",
					},
				})
				return
			}
			if !am.ValidateAPIKey(apiKey) {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"error": map[string]string{"message": "invalid API key", "type": "authentication_error"},
				})
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// /api/* utilise une session
		if strings.HasPrefix(path, "/api/") {
			token := extractToken(r)
			if token == "" || !am.IsValid(token) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// HandleLogin POST /api/login
func (am *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, ok, wait := am.Login(body.Username, body.Password, clientIP(r))
	if !ok {
		if wait > 0 {
			writeAPIError(w, http.StatusTooManyRequests,
				fmt.Sprintf("Trop de tentatives de connexion, réessayez dans %d secondes", int(wait.Seconds())+1))
			return
		}
		writeAPIError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(sessionExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":             true,
		"token":               token,
		"username":            body.Username,
		"is_default_password": am.isDefaultPassword(),
	})
}

// HandleLogout POST /api/logout
func (am *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if token := extractToken(r); token != "" {
		am.Logout(token)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logout success"})
}

// HandleCheckAuth GET /api/auth/check
func (am *AuthManager) HandleCheckAuth(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" && am.IsValid(token) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated":       true,
			"is_default_password": am.isDefaultPassword(),
		})
		return
	}
	writeAPIError(w, http.StatusUnauthorized, "not authenticated")
}

// HandleChangePassword POST /api/auth/password
func (am *AuthManager) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.NewPassword == "" {
		writeAPIError(w, http.StatusBadRequest, "new_password is required")
		return
	}
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.verifyPassword(body.OldPassword) {
		writeAPIError(w, http.StatusUnauthorized, "old password incorrect")
		return
	}
	if am.db != nil {
		if err := am.db.SetPasswordHash(hashPassword(body.NewPassword)); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to save password")
			return
		}
		am.db.SetDefaultPasswordFlag(false)
	}
	am.sessions = make(map[string]*sessionEntry)
	log.Printf("[auth] password changed, all sessions invalidated")
	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed, please re-login"})
}

// HandleGetAPIKey GET /api/settings/api-key
func (am *AuthManager) HandleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := am.db.GetAPIKey()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"api_key": key, "has_api_key": key != ""})
}

// HandleGenerateAPIKey POST /api/settings/api-key/generate
func (am *AuthManager) HandleGenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	newKey := GenerateAPIKey()
	if err := am.db.SetAPIKey(newKey); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("[auth] API key generated: %s...%s", newKey[:8], newKey[len(newKey)-4:])
	writeJSON(w, http.StatusOK, map[string]interface{}{"api_key": newKey, "message": "API key generated"})
}

// ---- Fonctions HTTP utilitaires ----

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{"message": msg, "type": "api_error"},
	})
}
