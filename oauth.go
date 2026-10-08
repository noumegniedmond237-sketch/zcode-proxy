package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---- Connexion par code d'autorisation OAuth Z.AI ----
// Portage de oauth.py de zcode2api :
//   Connexion directe (loopback) : redirect_uri=http://127.0.0.1:{port}/oauth/callback, state=hex aléatoire
//   Collage manuel (manual) :       redirect_uri=https://zcode.z.ai/login, state=base64url(JSON{nonce,...})
// Échange : POST zcode.z.ai/api/v1/oauth/token {"provider":"zai","code","redirect_uri","state"}
//   → data{token(Coding Plan JWT), zai{access_token,refresh_token}, user{...}}
// Chaîne d'extraction de la clé API : z/login → getCustomerInfo → api_keys → copy → {key}.{secret}

const (
	OAuthAuthorizeURL = "https://chat.z.ai/api/oauth/authorize"
	OAuthTokenURL     = "https://zcode.z.ai/api/v1/oauth/token"
	OAuthUserInfoURL  = "https://chat.z.ai/api/oauth/userinfo"
	OAuthClientID     = "client_P8X5CMWmlaRO9gyO-KSqtg"
	OAuthManualRedirect = "https://zcode.z.ai/login"
	BizLoginURL       = "https://api.z.ai/api/auth/z/login"
	CustomerInfoURL   = "https://api.z.ai/api/biz/customer/getCustomerInfo"
)

// OAuthFlow état d'un flux de connexion
type OAuthFlow struct {
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	Manual      bool   `json:"manual"`
	Group       string `json:"group"`
	CreatedAt   int64  `json:"created_at"`
	Status      string `json:"status"` // pending | exchanging | ready | failed
	Message     string `json:"message"`
	AccountID   int64  `json:"account_id"`
	Email       string `json:"email"`
	AuthorizeURL string `json:"authorize_url"`
}

// OAuthManager gestionnaire de connexion OAuth
type OAuthManager struct {
	db   *DB
	zapi *ZCodeAPI
	port int // Port d'écoute local (pour loopback redirect_uri)

	mu    sync.Mutex
	flows map[string]*OAuthFlow
}

// NewOAuthManager crée le gestionnaire OAuth ; listenAddr sous forme 127.0.0.1:8687
func NewOAuthManager(db *DB, zapi *ZCodeAPI, listenAddr string) *OAuthManager {
	port := 8687
	if idx := strings.LastIndex(listenAddr, ":"); idx >= 0 {
		if p, err := strconv.Atoi(listenAddr[idx+1:]); err == nil {
			port = p
		}
	}
	return &OAuthManager{db: db, zapi: zapi, port: port, flows: make(map[string]*OAuthFlow)}
}

// StartLogin initialise un flux de connexion et renvoie (flow, URL d'autorisation)
func (m *OAuthManager) StartLogin(manual bool, group string) (*OAuthFlow, string) {
	var state, redirectURI string
	if manual {
		nonce := uuid.NewString()
		redirectURI = OAuthManualRedirect
		stateJSON, _ := json.Marshal(map[string]string{
			"nonce":         nonce,
			"app_return_to": redirectURI,
			"redirect_uri":  redirectURI,
		})
		state = base64.RawURLEncoding.EncodeToString(stateJSON)
	} else {
		state = strings.ReplaceAll(uuid.NewString(), "-", "")[:32]
		redirectURI = fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", m.port)
	}
	authURL := OAuthAuthorizeURL + "?" + url.Values{
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"client_id":     {OAuthClientID},
		"state":         {state},
	}.Encode()

	flow := &OAuthFlow{
		State: state, RedirectURI: redirectURI, Manual: manual, Group: group,
		CreatedAt: time.Now().Unix(), Status: "pending", AuthorizeURL: authURL,
	}
	m.mu.Lock()
	m.flows[state] = flow
	// Nettoyage des flux expirés après 10 minutes
	for k, f := range m.flows {
		if time.Now().Unix()-f.CreatedAt > 600 {
			delete(m.flows, k)
		}
	}
	m.mu.Unlock()
	return flow, authURL
}

// HandleCallback callback de redirection du navigateur : capture code -> échange -> renvoie la page de résultat
func (m *OAuthManager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := strings.TrimSpace(q.Get("state"))
	code := strings.TrimSpace(q.Get("code"))
	errParam := strings.TrimSpace(q.Get("error"))
	errDesc := strings.TrimSpace(q.Get("error_description"))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	m.mu.Lock()
	flow, ok := m.flows[state]
	m.mu.Unlock()
	if !ok {
		fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
			<h2>❌ Flux de connexion introuvable ou expiré</h2><p>Veuillez relancer la connexion depuis l'interface de gestion</p></body></html>`)
		return
	}
	if errParam != "" {
		m.finishFlow(flow, "", fmt.Sprintf("Autorisation refusée : %s", firstNonEmpty(errDesc, errParam)))
		fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
			<h2>❌ Autorisation refusée</h2><p>`+escapeHTML(firstNonEmpty(errDesc, errParam))+`</p></body></html>`)
		return
	}
	if code == "" {
		fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
			<h2>❌ Le callback ne contient aucun code</h2></body></html>`)
		return
	}

	// Échange synchrone
	m.setFlowStatus(flow, "exchanging", "Échange du token en cours…")
	log.Printf("[oauth] callback arrived: state=%s… code_len=%d", safePrefixLog(state, 8), len(code))
	if err := m.completeFlow(flow, code); err != nil {
		fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
			<h2>❌ Échec d'échange du code d'autorisation</h2><p>`+escapeHTML(err.Error())+`</p>
			<p style="color:#666;font-size:13px">Vous pouvez réessayer via « Connexion OAuth → Collage manuel ».</p>
			</body></html>`)
		return
	}
	email := ""
	m.mu.Lock()
	email = flow.Email
	m.mu.Unlock()
	fmt.Fprint(w, `<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
		<h2>✅ Autorisation réussie</h2><p>Le compte `+escapeHTML(email)+` a été enregistré, vous pouvez fermer cet onglet.</p>
		<script>setTimeout(function(){window.close()},3000)</script></body></html>`)
}

// safePrefixLog préfixe sécurisé pour les logs
func safePrefixLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// SubmitManual mode de collage manuel : soumission de l'URL de retour ou du code
func (m *OAuthManager) SubmitManual(state, raw string) error {
	m.mu.Lock()
	flow, ok := m.flows[state]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("Flux de connexion inexistant ou expiré")
	}
	code := ExtractOAuthCode(raw)
	if code == "" {
		return fmt.Errorf("Impossible d'extraire le code d'autorisation de l'entrée")
	}
	m.setFlowStatus(flow, "exchanging", "Échange du token en cours…")
	log.Printf("[oauth] manual submit: state=%s… code_len=%d", safePrefixLog(state, 8), len(code))
	return m.completeFlow(flow, code)
}

// ExtractOAuthCode extrait le code même si l'URL complète a été collée
func ExtractOAuthCode(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if strings.Contains(raw, "code=") {
		if u, err := url.Parse(raw); err == nil {
			return u.Query().Get("code")
		}
		return ""
	}
	return raw
}

// FlowStatus interroge le statut du flux (sondé par l'UI)
func (m *OAuthManager) FlowStatus(state string) *OAuthFlow {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[state]
	if !ok {
		return nil
	}
	cp := *f
	return &cp
}

func (m *OAuthManager) setFlowStatus(f *OAuthFlow, status, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.Status = status
	f.Message = msg
}

func (m *OAuthManager) finishFlow(f *OAuthFlow, email, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if errMsg != "" {
		f.Status = "failed"
		f.Message = errMsg
	} else {
		f.Status = "ready"
		f.Email = email
	}
}

// ---- Processus d'échange ----

// completeFlow code → token → API Key → enregistrement du compte
func (m *OAuthManager) completeFlow(flow *OAuthFlow, code string) error {
	data, err := m.exchangeToken(code, flow.State, flow.RedirectURI)
	if err != nil {
		m.finishFlow(flow, "", "Échec d'échange du token : "+err.Error())
		log.Printf("[oauth] exchange failed: %v", err)
		return fmt.Errorf("Échec d'échange du token : %w", err)
	}

	jwt := jsonStr(data, "token")
	if jwt == "" {
		m.finishFlow(flow, "", "Les données retournées ne contiennent aucun JWT Coding Plan")
		return fmt.Errorf("Les données retournées ne contiennent aucun JWT Coding Plan")
	}
	zai, _ := data["zai"].(map[string]interface{})
	accessToken := jsonStr(zai, "access_token")
	refreshToken := jsonStr(zai, "refresh_token")
	user, _ := data["user"].(map[string]interface{})
	if user == nil {
		user = map[string]interface{}{}
	}

	// Compléter les informations utilisateur si manquantes
	if jsonStr(user, "email") == "" && jsonStr(user, "user_id") == "" && accessToken != "" {
		if ui := m.fetchUserInfo(accessToken); ui != nil {
			user = ui
		}
	}

	userInfoJSON, _ := json.Marshal(user)
	email := jsonStr(user, "email")
	userID := firstNonEmpty(jsonStr(user, "user_id"), jsonStr(user, "id"))
	if userID == "" {
		if claims, err := DecodeJWTPayload(jwt); err == nil {
			userID = firstNonEmpty(jsonStr(claims, "user_id"), jsonStr(claims, "sub"))
		}
	}
	if userID == "" {
		userID = "oauth-" + uuid.NewString()[:8]
	}

	a := &Account{
		UserID:       userID,
		Email:        email,
		DisplayName:  oauthDisplayName(user),
		Provider:     "zai",
		AuthType:     "jwt",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ZCodeJWT:     jwt,
		UserInfo:     string(userInfoJSON),
		DeviceMid:    LocalDeviceMid(),
		Status:       StatusActive,
		Enabled:      true,
		AccountGroup: flow.Group,
	}

	// Chaîne d'extraction de la clé API (au mieux : l'échec n'empêche pas l'enregistrement du compte JWT)
	if accessToken != "" {
		if apiKey, err := m.exchangeAPIKey(accessToken); err != nil {
			log.Printf("[oauth] api key extraction failed for %s: %v", email, err)
		} else {
			a.APIKey = apiKey
			log.Printf("[oauth] api key extracted for %s", email)
		}
	}

	id, err := m.db.UpsertAccount(a)
	if err != nil {
		m.finishFlow(flow, "", "Échec d'enregistrement du compte : "+err.Error())
		return fmt.Errorf("Échec d'enregistrement du compte : %w", err)
	}
	a.ID = id
	m.mu.Lock()
	flow.AccountID = id
	m.mu.Unlock()
	m.finishFlow(flow, email, "")
	log.Printf("[oauth] login success: %s (id=%d)", email, id)

	// Actualisation asynchrone du quota pour confirmer le statut
	go func() {
		time.Sleep(time.Second)
		if err := m.zapi.RefreshAccountQuota(a); err != nil {
			log.Printf("[oauth] initial quota refresh %s: %v", email, err)
		}
	}()
	return nil
}

// exchangeToken POST /api/v1/oauth/token
func (m *OAuthManager) exchangeToken(code, state, redirectURI string) (map[string]interface{}, error) {
	payload, _ := json.Marshal(map[string]string{
		"provider":     "zai",
		"code":         code,
		"redirect_uri": redirectURI,
		"state":        state,
	})
	client := ClientForURL(m.zapi.egress.GlobalProxyURL(), OAuthTokenURL, 30*time.Second)
	resp, err := client.Post(OAuthTokenURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var v map[string]interface{}
	json.Unmarshal(body, &v)
	if len(v) == 0 && resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	// Code métier (0, 200 ou absent)
	if codeVal, has := v["code"]; has {
		n := jsonInt(v, "code")
		if n != 0 && n != 200 {
			msg := firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message"))
			if msg == "" {
				msg = truncate(string(body), 200)
			}
			return nil, fmt.Errorf("Code métier %d : %s (HTTP %d)", n, msg, resp.StatusCode)
		}
		_ = codeVal
	}
	data, ok := v["data"].(map[string]interface{})
	if !ok || jsonStr(data, "token") == "" {
		return nil, fmt.Errorf("Les données retournées ne contiennent aucun JWT Coding Plan")
	}
	return data, nil
}

// fetchUserInfo GET chat.z.ai/api/oauth/userinfo
func (m *OAuthManager) fetchUserInfo(accessToken string) map[string]interface{} {
	client := NewUpstreamHTTPClient(m.zapi.egress.GlobalProxyURL(), 15*time.Second)
	req, _ := http.NewRequest("GET", OAuthUserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var v map[string]interface{}
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	if d, ok := v["data"].(map[string]interface{}); ok {
		return d
	}
	return nil
}

// exchangeAPIKey OAuth access_token → token métier → organisation/projet → clé API
func (m *OAuthManager) exchangeAPIKey(accessToken string) (string, error) {
	client := NewUpstreamHTTPClient(m.zapi.egress.GlobalProxyURL(), 30*time.Second)

	// 1. z/login pour obtenir le token métier
	loginBody, _ := json.Marshal(map[string]string{"token": accessToken})
	resp, err := client.Post(BizLoginURL, "application/json", bytes.NewReader(loginBody))
	if err != nil {
		return "", err
	}
	bizToken, err := readDataString(resp, "access_token", "accessToken")
	if err != nil {
		return "", fmt.Errorf("Échec de connexion métier : %w", err)
	}

	// 2. getCustomerInfo pour trouver l'organisation et le projet par défaut
	req, _ := http.NewRequest("GET", CustomerInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+bizToken)
	resp2, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4<<20))
	resp2.Body.Close()
	var info struct {
		Data struct {
			Organizations []struct {
				OrganizationID   interface{} `json:"organizationId"`
				OrganizationName string      `json:"organizationName"`
				Projects         []struct {
					ProjectID   interface{} `json:"projectId"`
					ProjectName string      `json:"projectName"`
				} `json:"projects"`
			} `json:"organizations"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body2, &info); err != nil {
		return "", fmt.Errorf("Échec d'analyse des informations d'organisation : %w", err)
	}
	orgs := info.Data.Organizations
	if len(orgs) == 0 {
		return "", fmt.Errorf("Aucune organisation disponible")
	}
	org := orgs[0]
	for _, o := range orgs {
		if strings.Contains(o.OrganizationName, "\u9ed8\u8ba4\u673a\u6784") {
			org = o
			break
		}
	}
	if len(org.Projects) == 0 {
		return "", fmt.Errorf("Aucun projet disponible")
	}
	proj := org.Projects[0]
	for _, p := range org.Projects {
		if strings.Contains(p.ProjectName, "\u9ed8\u8ba4\u9879\u76ee") {
			proj = p
			break
		}
	}
	orgID := fmt.Sprintf("%v", org.OrganizationID)
	projID := fmt.Sprintf("%v", proj.ProjectID)
	keyURL := fmt.Sprintf("https://api.z.ai/api/biz/v1/organization/%s/projects/%s/api_keys", orgID, projID)

	// 3. Lister les api_keys, trouver ou créer zcode-api-key
	req3, _ := http.NewRequest("GET", keyURL, nil)
	req3.Header.Set("Authorization", "Bearer "+bizToken)
	resp3, err := client.Do(req3)
	if err != nil {
		return "", err
	}
	body3, _ := io.ReadAll(io.LimitReader(resp3.Body, 4<<20))
	resp3.Body.Close()
	var keysResp struct {
		Data []struct {
			Name   string `json:"name"`
			APIKey string `json:"apiKey"`
		} `json:"data"`
	}
	json.Unmarshal(body3, &keysResp)
	apiKey := ""
	for _, k := range keysResp.Data {
		if k.Name == "zcode-api-key" && k.APIKey != "" {
			apiKey = k.APIKey
			break
		}
	}
	if apiKey == "" {
		createBody, _ := json.Marshal(map[string]string{"name": "zcode-api-key"})
		req4, _ := http.NewRequest("POST", keyURL, bytes.NewReader(createBody))
		req4.Header.Set("Authorization", "Bearer "+bizToken)
		req4.Header.Set("Content-Type", "application/json")
		resp4, err := client.Do(req4)
		if err != nil {
			return "", err
		}
		body4, _ := io.ReadAll(io.LimitReader(resp4.Body, 1<<20))
		resp4.Body.Close()
		var created struct {
			Data struct {
				APIKey string `json:"apiKey"`
			} `json:"data"`
		}
		json.Unmarshal(body4, &created)
		apiKey = created.Data.APIKey
	}
	if apiKey == "" {
		return "", fmt.Errorf("Impossible d'obtenir la clé API")
	}

	// 4. Copier la clé pour obtenir le secretKey
	req5, _ := http.NewRequest("GET", keyURL+"/copy/"+apiKey, nil)
	req5.Header.Set("Authorization", "Bearer "+bizToken)
	resp5, err := client.Do(req5)
	if err != nil {
		return "", err
	}
	secretKey, err := readDataString(resp5, "secretKey")
	if err != nil {
		return "", fmt.Errorf("Impossible de déchiffrer la Secret Key : %w", err)
	}
	return apiKey + "." + secretKey, nil
}

// readDataString extrait une chaîne par clé candidate depuis la réponse data
func readDataString(resp *http.Response, keys ...string) (string, error) {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 150))
	}
	var v map[string]interface{}
	if json.Unmarshal(body, &v) != nil {
		return "", fmt.Errorf("Réponse non JSON")
	}
	data, _ := v["data"].(map[string]interface{})
	if data == nil {
		return "", fmt.Errorf("data manquant dans la réponse")
	}
	for _, k := range keys {
		if s := jsonStr(data, k); s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("data ne contient aucun de %v", keys)
}

// oauthDisplayName nom d'affichage : pseudo → préfixe email → téléphone
func oauthDisplayName(user map[string]interface{}) string {
	pick := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := user[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}
	if name := pick("name", "username", "nickName", "nickname", "displayName"); name != "" {
		return name
	}
	if email := pick("email", "mail"); strings.Contains(email, "@") {
		return strings.SplitN(email, "@", 2)[0]
	}
	if phone := pick("phone", "phone_number", "phoneNumber", "mobile"); phone != "" {
		return "Compte " + phone
	}
	return ""
}

func escapeHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
