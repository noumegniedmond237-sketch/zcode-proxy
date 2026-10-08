package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---- Gestion des comptes : import du client local / import par collage / rebascule en un clic ----

// AccountManager gère les sources de comptes
type AccountManager struct {
	db    *DB
	zapi  *ZCodeAPI
	oauth *OAuthManager
}

// NewAccountManager crée le gestionnaire de comptes
func NewAccountManager(db *DB, zapi *ZCodeAPI, oauth *OAuthManager) *AccountManager {
	return &AccountManager{db: db, zapi: zapi, oauth: oauth}
}

// ---- Import depuis le client local ----

// localClientFiles chemins des fichiers liés au client ZCode local
type localClientFiles struct {
	home        string
	credentials string // ~/.zcode/v2/credentials.json
	config      string // ~/.zcode/v2/config.json
	telemetry   string // ~/.zcode/v2/telemetry-state.json
	cache       string // ~/.zcode/v2/coding-plan-cache.json
}

func resolveLocalClientFiles() localClientFiles {
	home, _ := os.UserHomeDir()
	v2 := filepath.Join(home, ".zcode", "v2")
	return localClientFiles{
		home:        home,
		credentials: filepath.Join(v2, "credentials.json"),
		config:      filepath.Join(v2, "config.json"),
		telemetry:   filepath.Join(v2, "telemetry-state.json"),
		cache:       filepath.Join(v2, "coding-plan-cache.json"),
	}
}

// ImportFromLocalClient importe le compte actuellement connecté depuis le client ZCode local.
// Déchiffre credentials.json pour extraire JWT/access_token/user_info ;
// extrait la API Key coding-plan de config.json ; conserve le contenu d'origine des fichiers pour la rebascule en un clic.
func (m *AccountManager) ImportFromLocalClient(group string) (*Account, error) {
	f := resolveLocalClientFiles()
	credData, err := os.ReadFile(f.credentials)
	if err != nil {
		return nil, fmt.Errorf("Échec de lecture des identifiants locaux (client ZCode peut-être absent/non connecté) : %w", err)
	}
	var creds map[string]string
	if err := json.Unmarshal(credData, &creds); err != nil {
		return nil, fmt.Errorf("Échec d'analyse du fichier d'identifiants : %w", err)
	}

	secret := DefaultCredentialSecret(f.home)
	dec := func(key string) string {
		v, ok := creds[key]
		if !ok {
			return ""
		}
		plain, err := DecryptCredential(v, secret)
		if err != nil {
			log.Printf("[import] decrypt %s: %v", key, err)
			return ""
		}
		return plain
	}

	provider := dec("oauth:active_provider")
	if provider == "" {
		provider = "zai"
	}
	zcodeJWT := dec("zcodejwttoken")
	accessToken := dec(fmt.Sprintf("oauth:%s:access_token", provider))
	userInfo := dec(fmt.Sprintf("oauth:%s:user_info", provider))
	if zcodeJWT == "" && accessToken == "" {
		return nil, fmt.Errorf("Aucune session ZCode valide dans les identifiants locaux (connectez-vous d'abord dans le client ZCode)")
	}

	// user_info → email/name/user_id
	var ui map[string]interface{}
	if userInfo != "" {
		json.Unmarshal([]byte(userInfo), &ui)
	}
	email := jsonStr(ui, "email")
	displayName := firstNonEmpty(jsonStr(ui, "name"), jsonStr(ui, "username"), jsonStr(ui, "displayName"))
	userID := firstNonEmpty(jsonStr(ui, "user_id"), jsonStr(ui, "id"))
	if userID == "" && zcodeJWT != "" {
		if claims, err := DecodeJWTPayload(zcodeJWT); err == nil {
			userID = firstNonEmpty(jsonStr(claims, "user_id"), jsonStr(claims, "sub"))
		}
	}
	if userID == "" && accessToken != "" {
		if claims, err := DecodeJWTPayload(accessToken); err == nil {
			userID = firstNonEmpty(jsonStr(claims, "user_id"), jsonStr(claims, "sub"))
		}
	}
	if userID == "" {
		return nil, fmt.Errorf("Impossible de déterminer le user_id du compte")
	}

	// device_mid
	deviceMid := ""
	if tData, err := os.ReadFile(f.telemetry); err == nil {
		var t struct {
			DeviceMid string `json:"deviceMid"`
		}
		if json.Unmarshal(tData, &t) == nil {
			deviceMid = t.DeviceMid
		}
	}

	// config.json → API Key coding-plan (déjà au format complet {id}.{secret})
	apiKey := ""
	if cData, err := os.ReadFile(f.config); err == nil {
		var cfg struct {
			Provider map[string]struct {
				Enabled *bool `json:"enabled"`
				Options struct {
					APIKey string `json:"apiKey"`
				} `json:"options"`
			} `json:"provider"`
		}
		if json.Unmarshal(cData, &cfg) == nil {
			for id, p := range cfg.Provider {
				if strings.Contains(id, "coding-plan") && strings.Contains(id, provider) &&
					p.Options.APIKey != "" && !strings.HasPrefix(p.Options.APIKey, "enc:") {
					apiKey = p.Options.APIKey
					break
				}
			}
		}
	}

	// Instantané des identifiants d'origine (pour restaurer la rebascule en un clic)
	snapshot := map[string]string{
		"credentials.json": string(credData),
	}
	if cData, err := os.ReadFile(f.config); err == nil {
		snapshot["config.json"] = string(cData)
	}
	snapshotJSON, _ := json.Marshal(snapshot)

	a := &Account{
		UserID:      userID,
		Email:       email,
		DisplayName: displayName,
		Provider:    provider,
		AuthType:    "jwt",
		AccessToken: accessToken,
		ZCodeJWT:    zcodeJWT,
		APIKey:      apiKey,
		UserInfo:    userInfo,
		DeviceMid:   deviceMid,
		CredsRaw:    string(snapshotJSON),
		Status:      StatusActive,
		Enabled:     true,
		AccountGroup: group,
		Remark:      "Import du client local",
	}
	if zcodeJWT == "" {
		a.AuthType = "apikey"
	}
	id, err := m.db.UpsertAccount(a)
	if err != nil {
		return nil, fmt.Errorf("Échec d'enregistrement du compte : %w", err)
	}
	a.ID = id
	log.Printf("[import] local client account imported: %s (id=%d, jwt=%v, apikey=%v)",
		email, id, zcodeJWT != "", apiKey != "")

	// Actualisation asynchrone du quota
	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := m.zapi.RefreshAccountQuota(a); err != nil {
			log.Printf("[import] quota refresh %s: %v", email, err)
		}
	}()
	return a, nil
}

// ---- Import par collage ----

// LooksLikeJWT vérifie si un identifiant a la forme d'un JWT (3 segments base64url)
func LooksLikeJWT(secret string) bool {
	parts := strings.Split(strings.TrimSpace(secret), ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
				return false
			}
		}
	}
	return true
}

// ImportPasted importe un JWT ou une API Key collé
func (m *AccountManager) ImportPasted(provider, name, secret, group string) (*Account, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, fmt.Errorf("Les identifiants ne peuvent pas être vides")
	}
	if provider == "" {
		provider = "zai"
	}
	isJWT := LooksLikeJWT(secret) && provider == "zai"

	// user_id : payload décodé du JWT ; pour une API Key, un hachage sert de clé naturelle
	userID := ""
	if isJWT {
		if claims, err := DecodeJWTPayload(secret); err == nil {
			userID = firstNonEmpty(jsonStr(claims, "user_id"), jsonStr(claims, "sub"))
		}
	}
	if userID == "" {
		h := sha256.Sum256([]byte(provider + ":" + secret))
		userID = provider + "-" + hex.EncodeToString(h[:8])
	}

	a := &Account{
		UserID:       userID,
		DisplayName:  strings.TrimSpace(name),
		Email:        "",
		Provider:     provider,
		Status:       StatusActive,
		Enabled:      true,
		AccountGroup: group,
		Remark:       "Import par collage",
	}
	if isJWT {
		a.AuthType = "jwt"
		a.ZCodeJWT = secret
	} else {
		a.AuthType = "apikey"
		a.APIKey = secret
	}
	id, err := m.db.UpsertAccount(a)
	if err != nil {
		return nil, fmt.Errorf("Échec d'enregistrement du compte : %w", err)
	}
	a.ID = id

	go func() {
		time.Sleep(500 * time.Millisecond)
		m.zapi.RefreshAccountQuota(a)
	}()
	return a, nil
}

// ---- Rebascule vers le client local en un clic ----

// SwitchBackToLocal réécrit les identifiants du compte sélectionné dans le client ZCode local :
//  1. instantané des credentials.json / config.json actuels dans data/backups/
//  2. réécriture de credentials.json chiffré à nouveau en enc:v1 (remplacement atomique)
//  3. mise à jour de l'apiKey start-plan / coding-plan et de enabled dans config.json
//  4. suppression de coding-plan-cache.json pour forcer le client à re-détecter le forfait
func (m *AccountManager) SwitchBackToLocal(accountID int64, killClient bool) error {
	a, err := m.db.GetAccount(accountID)
	if err != nil {
		return err
	}
	if a.ZCodeJWT == "" {
		return fmt.Errorf("Ce compte n'a pas de JWT ZCode, rebascule vers le client local impossible")
	}
	f := resolveLocalClientFiles()
	secret := DefaultCredentialSecret(f.home)

	// 1. Sauvegarde (basée sur le répertoire de l'exécutable, pour éviter l'influence du répertoire de travail)
	backupDir := filepath.Join(exeDir(), "data", "backups")
	os.MkdirAll(backupDir, 0755)
	stamp := time.Now().Format("20060102-150405")
	for _, p := range []string{f.credentials, f.config} {
		if data, err := os.ReadFile(p); err == nil {
			os.WriteFile(filepath.Join(backupDir, filepath.Base(p)+"."+stamp+".bak"), data, 0644)
		}
	}

	// 2. Reconstruction de credentials.json : conserve les clés non concernées (bot/web-remote-control, etc.), ne remplace que l'état de connexion
	var creds map[string]string
	if data, err := os.ReadFile(f.credentials); err == nil {
		json.Unmarshal(data, &creds)
	}
	if creds == nil {
		creds = map[string]string{}
	}
	provider := a.Provider
	if provider == "" {
		provider = "zai"
	}
	enc := func(plain string) (string, error) { return EncryptCredential(plain, secret) }

	if v, err := enc(a.ZCodeJWT); err == nil {
		creds["zcodejwttoken"] = v
	}
	if a.AccessToken != "" {
		if v, err := enc(a.AccessToken); err == nil {
			creds["oauth:"+provider+":access_token"] = v
		}
	}
	if a.UserInfo != "" {
		if v, err := enc(a.UserInfo); err == nil {
			creds["oauth:"+provider+":user_info"] = v
		}
	}
	if v, err := enc(provider); err == nil {
		creds["oauth:active_provider"] = v
	}
	if err := atomicWriteJSON(f.credentials, creds); err != nil {
		return fmt.Errorf("Échec de réécriture de credentials.json : %w", err)
	}

	// 3. Mise à jour du provider dans config.json
	var cfg map[string]interface{}
	if data, err := os.ReadFile(f.config); err == nil {
		if json.Unmarshal(data, &cfg) != nil {
			cfg = nil
		}
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	providers, _ := cfg["provider"].(map[string]interface{})
	if providers == nil {
		providers = map[string]interface{}{}
		cfg["provider"] = providers
	}
	setProviderKey := func(id, key string, enable bool) {
		p, _ := providers[id].(map[string]interface{})
		if p == nil {
			p = map[string]interface{}{}
			providers[id] = p
		}
		opts, _ := p["options"].(map[string]interface{})
		if opts == nil {
			opts = map[string]interface{}{}
			p["options"] = opts
		}
		opts["apiKey"] = key
		p["enabled"] = enable
	}
	setProviderKey("builtin:"+provider+"-start-plan", a.ZCodeJWT, true)
	if a.APIKey != "" {
		setProviderKey("builtin:"+provider+"-coding-plan", a.APIKey, true)
	}
	if err := atomicWriteJSON(f.config, cfg); err != nil {
		return fmt.Errorf("Échec de réécriture de config.json : %w", err)
	}

	// 4. Purge du cache pour forcer une nouvelle détection
	os.Remove(f.cache)

	log.Printf("[switch-back] account %s written to local client", a.Email)

	// 5. Optionnel : terminer le processus ZCode pour appliquer les changements
	if killClient {
		killZCodeProcess()
	}
	return nil
}

// atomicWriteJSON écriture atomique via fichier temporaire + rename
func atomicWriteJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp-zproxy"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// killZCodeProcess termine le processus du client ZCode local (implémentation par plateforme : proc_windows.go / proc_other.go)
func killZCodeProcess() {
	out, err := killProcessByName("ZCode.exe")
	if err != nil {
		log.Printf("[switch-back] kill ZCode.exe: %v (%s)", err, strings.TrimSpace(out))
		return
	}
	log.Printf("[switch-back] ZCode.exe terminated")
}

// exeDir renvoie le répertoire de l'exécutable (base des chemins de sauvegarde/données)
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// RestoreLocalFromSnapshot restaure le client local depuis l'instantané d'import (annule la rebascule)
func (m *AccountManager) RestoreLocalFromSnapshot(accountID int64) error {
	a, err := m.db.GetAccount(accountID)
	if err != nil {
		return err
	}
	if a.CredsRaw == "" {
		return fmt.Errorf("Ce compte n'a pas d'instantané d'identifiants locaux, restauration impossible")
	}
	var snapshot map[string]string
	if err := json.Unmarshal([]byte(a.CredsRaw), &snapshot); err != nil {
		return fmt.Errorf("Échec d'analyse de l'instantané : %w", err)
	}
	f := resolveLocalClientFiles()
	targets := map[string]string{
		"credentials.json": f.credentials,
		"config.json":      f.config,
	}
	for name, content := range snapshot {
		path, ok := targets[name]
		if !ok || content == "" {
			continue
		}
		tmp := path + ".tmp-zproxy"
		if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	os.Remove(f.cache)
	log.Printf("[switch-back] local client restored from snapshot of account %s", a.Email)
	return nil
}
