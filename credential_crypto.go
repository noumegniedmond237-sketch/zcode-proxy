package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ---- Chiffrement / déchiffrement des identifiants locaux ZCode enc:v1 ----
// Format : "enc:v1:" + b64url(nonce12) + "." + b64url(tag16) + "." + b64url(ciphertext)
// Clé : SHA-256(secret), secret = variable d'environnement ZCODE_CREDENTIAL_SECRET
//       ou repli "zcode-credential-fallback:{plateforme node}:{home}:{nom d'utilisateur}"
// Compatible octet par octet avec zcode-switch/src-tauri/src/zcrypto.rs.

const encPrefix = "enc:v1:"

var b64URLNoPad = base64.RawURLEncoding

// NodePlatform retourne le nom de plateforme au sens Node.js (identique au client ZCode)
func NodePlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "win32"
	case "darwin":
		return "darwin"
	default:
		return runtime.GOOS
	}
}

// DefaultCredentialSecret calcule la clé d'identifiants par défaut.
// Si home est vide, USERPROFILE / HOME est détecté automatiquement.
func DefaultCredentialSecret(home string) string {
	if s := os.Getenv("ZCODE_CREDENTIAL_SECRET"); s != "" {
		return s
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	username := os.Getenv("USERNAME") // Windows
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	if username == "" {
		username = "unknown"
	}
	return fmt.Sprintf("zcode-credential-fallback:%s:%s:%s", NodePlatform(), home, username)
}

func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// IsEncryptedValue indique si une valeur est un chiffré enc:v1
func IsEncryptedValue(v string) bool {
	return strings.HasPrefix(v, encPrefix)
}

// DecryptCredential déchiffre une valeur enc:v1 ; le clair est retourné tel quel
func DecryptCredential(value, secret string) (string, error) {
	if !IsEncryptedValue(value) {
		return value, nil
	}
	body := strings.TrimPrefix(value, encPrefix)
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("Format enc:v1 invalide")
	}
	nonce, err := b64URLNoPad.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("Échec du décodage du nonce: %w", err)
	}
	tag, err := b64URLNoPad.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("Échec du décodage du tag: %w", err)
	}
	ct, err := b64URLNoPad.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("Échec du décodage du chiffré: %w", err)
	}
	if len(nonce) != 12 {
		return "", fmt.Errorf("Longueur de nonce anormale: %d", len(nonce))
	}
	block, err := aes.NewCipher(deriveKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Rust aes-gcm produit ct||tag, Go GCM Open attend de même ct||tag
	buf := append(append([]byte{}, ct...), tag...)
	pt, err := gcm.Open(nil, nonce, buf, nil)
	if err != nil {
		return "", fmt.Errorf("Échec du déchiffrement (clé incorrecte ou données endommagées)")
	}
	return string(pt), nil
}

// EncryptCredential chiffre au format enc:v1 (réécriture vers le client local lors du rebascule en un clic)
func EncryptCredential(plain, secret string) (string, error) {
	block, err := aes.NewCipher(deriveKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), nil) // ct||tag
	ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	return fmt.Sprintf("%s%s.%s.%s", encPrefix,
		b64URLNoPad.EncodeToString(nonce),
		b64URLNoPad.EncodeToString(tag),
		b64URLNoPad.EncodeToString(ct)), nil
}

// DecodeJWTPayload extrait le payload JSON d'un JWT (sans vérifier la signature, lecture seule des claims)
func DecodeJWTPayload(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Format JWT invalide")
	}
	payload, err := b64URLNoPad.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ZCodeHome retourne le répertoire de données ZCode local (~/.zcode)
func ZCodeHome() string {
	if h := os.Getenv("ZCODE_SWITCH_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".zcode")
}

// LocalCredentialsPath chemin du fichier d'identifiants du client local
func LocalCredentialsPath() string {
	h := ZCodeHome()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "v2", "credentials.json")
}

// LocalTelemetryPath telemetry-state.json local (source de deviceMid)
func LocalTelemetryPath() string {
	h := ZCodeHome()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "v2", "telemetry-state.json")
}
