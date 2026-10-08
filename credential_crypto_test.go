package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestEncV1Roundtrip cohérence chiffrement/déchiffrement enc:v1
func TestEncV1Roundtrip(t *testing.T) {
	secret := "zcode-credential-fallback:win32:C:\\Users\\test:test"
	// Donnée de test multilingue (UTF-8 multi-octets conservée pour valider le chiffrement)
	for _, plain := range []string{"hello", "中文内容测试", `{"a":1}`, strings.Repeat("x", 500)} {
		enc, err := EncryptCredential(plain, secret)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if !strings.HasPrefix(enc, "enc:v1:") {
			t.Fatalf("missing prefix: %s", enc)
		}
		if strings.Count(enc, ".") != 2 {
			t.Fatalf("bad segment count: %s", enc)
		}
		got, err := DecryptCredential(enc, secret)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != plain {
			t.Fatalf("roundtrip mismatch")
		}
	}
}

// TestEncV1CrossLanguageVector interopérabilité avec les vecteurs de test zcode-switch
// Vecteur issu de refs/zcode-switch/src-tauri/test-vectors/node-enc-v1.json (chiffré côté Node, vérifié côté Rust)
func TestEncV1CrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile(`refs\zcode-switch\src-tauri\test-vectors\node-enc-v1.json`)
	if err != nil {
		// Le fichier de vecteur peut manquer dans un clone superficiel, ignorer
		t.Skipf("vector file missing: %v", err)
	}
	var v struct {
		Secret string `json:"secret"`
		Enc    string `json:"enc"`
		Plain  string `json:"plain"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	got, err := DecryptCredential(v.Enc, v.Secret)
	if err != nil {
		t.Fatalf("decrypt vector: %v", err)
	}
	if got != v.Plain {
		t.Fatalf("vector mismatch: got %q want %q", got, v.Plain)
	}
}

// TestDefaultSecretFormat format du secret de secours
func TestDefaultSecretFormat(t *testing.T) {
	os.Unsetenv("ZCODE_CREDENTIAL_SECRET")
	s := DefaultCredentialSecret(`C:\Users\john`)
	if !strings.HasPrefix(s, "zcode-credential-fallback:") {
		t.Fatalf("bad prefix: %s", s)
	}
	if !strings.Contains(s, `C:\Users\john`) {
		t.Fatalf("home not embedded: %s", s)
	}
}

// TestLooksLikeJWT détection de la forme JWT
func TestLooksLikeJWT(t *testing.T) {
	if !LooksLikeJWT("eyJhbGci.eyJzdWIi.c2ln") {
		t.Fatal("should be jwt")
	}
	if LooksLikeJWT("sk-abc123") {
		t.Fatal("api key misdetected as jwt")
	}
	if LooksLikeJWT("a.b.") {
		t.Fatal("empty segment accepted")
	}
}

// TestDecodeJWTPayload analyse du payload JWT
func TestDecodeJWTPayload(t *testing.T) {
	// payload = {"user_id":"123456","sub":"s"}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Iiwic3ViIjoicyJ9.c2ln"
	claims, err := DecodeJWTPayload(jwt)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims["user_id"] != "123456" {
		t.Fatalf("bad claim: %v", claims)
	}
}
