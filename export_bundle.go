package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ---- Export / import du paquet de comptes chiffré ----
// Format : "zcb1:" + base64( salt(16) || nonce(12) || ciphertext )
// Clé : PBKDF2-SHA256(password, salt, 120000, 32) → AES-256-GCM
// Pour migrer les comptes entre machines (inclut JWT / API Key / empreinte appareil / instantané d'identifiants).

const bundlePrefix = "zcb1:"

const pbkdf2Iterations = 120000

// bundleAccount structure d'un compte dans le paquet (sans ID interne, upsert sur user_id à l'import)
type bundleAccount struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Provider     string `json:"provider"`
	AuthType     string `json:"auth_type"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ZCodeJWT     string `json:"zcode_jwt,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	UserInfo     string `json:"user_info,omitempty"`
	DeviceMid    string `json:"device_mid,omitempty"`
	CredsRaw     string `json:"creds_raw,omitempty"`
	AccountGroup string `json:"account_group,omitempty"`
	Remark       string `json:"remark,omitempty"`
}

// ExportBundle exporte tout (ou une sélection) des comptes sous forme de paquet chiffré
func (m *AccountManager) ExportBundle(password string, ids []int64) (string, error) {
	if password == "" {
		return "", fmt.Errorf("Veuillez définir un mot de passe d'export")
	}
	all, err := m.db.ListAccounts("")
	if err != nil {
		return "", err
	}
	want := map[int64]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var items []bundleAccount
	for _, a := range all {
		if len(want) > 0 && !want[a.ID] {
			continue
		}
		items = append(items, bundleAccount{
			UserID: a.UserID, Email: a.Email, DisplayName: a.DisplayName,
			Provider: a.Provider, AuthType: a.AuthType,
			AccessToken: a.AccessToken, RefreshToken: a.RefreshToken,
			ZCodeJWT: a.ZCodeJWT, APIKey: a.APIKey, UserInfo: a.UserInfo,
			DeviceMid: a.DeviceMid, CredsRaw: a.CredsRaw,
			AccountGroup: a.AccountGroup, Remark: a.Remark,
		})
	}
	if len(items) == 0 {
		return "", fmt.Errorf("Aucun compte à exporter")
	}
	plain, err := json.Marshal(map[string]interface{}{"version": 1, "accounts": items})
	if err != nil {
		return "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)

	raw := append(append(append([]byte{}, salt...), nonce...), ct...)
	return bundlePrefix + base64.StdEncoding.EncodeToString(raw), nil
}

// ImportBundle déchiffre et importe un paquet de comptes, retourne le nombre importé
func (m *AccountManager) ImportBundle(password, bundle string) (int, error) {
	bundle = strings.TrimSpace(bundle)
	if !strings.HasPrefix(bundle, bundlePrefix) {
		return 0, fmt.Errorf("Paquet de comptes invalide (préfixe zcb1: manquant)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(bundle, bundlePrefix))
	if err != nil {
		return 0, fmt.Errorf("Échec du décodage base64 du paquet")
	}
	if len(raw) < 16+12+16 {
		return 0, fmt.Errorf("Données du paquet trop courtes")
	}
	salt, nonce, ct := raw[:16], raw[16:28], raw[28:]
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, fmt.Errorf("Échec du déchiffrement : mot de passe incorrect ou paquet endommagé")
	}
	var payload struct {
		Accounts []bundleAccount `json:"accounts"`
	}
	if err := json.Unmarshal(plain, &payload); err != nil {
		return 0, fmt.Errorf("Échec de l'analyse du contenu du paquet")
	}
	count := 0
	for _, it := range payload.Accounts {
		if it.UserID == "" || (it.ZCodeJWT == "" && it.APIKey == "") {
			continue
		}
		a := &Account{
			UserID: it.UserID, Email: it.Email, DisplayName: it.DisplayName,
			Provider: firstNonEmpty(it.Provider, "zai"), AuthType: firstNonEmpty(it.AuthType, "jwt"),
			AccessToken: it.AccessToken, RefreshToken: it.RefreshToken,
			ZCodeJWT: it.ZCodeJWT, APIKey: it.APIKey, UserInfo: it.UserInfo,
			DeviceMid: it.DeviceMid, CredsRaw: it.CredsRaw,
			AccountGroup: it.AccountGroup, Remark: it.Remark,
			Status: StatusActive, Enabled: true,
		}
		if _, err := m.db.UpsertAccount(a); err == nil {
			count++
		}
	}
	return count, nil
}
