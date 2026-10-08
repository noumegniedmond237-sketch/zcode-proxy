package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---- Détection d'activités / réclamation / activation de forfait ----
// Portage de zcode-switch claim.rs :
//   détection : GET  zcode.z.ai/api/v1/zcode-plan/billing/preview?app_version&platform
//   réclamation : POST zcode.z.ai/api/v1/zcode-plan/billing/claim {"plan_id"} + en-tête de captcha Aliyun
//   activation : POST zcode.z.ai/api/v1/event/report (deux événements app_launch + app_daily_active)

// GrantItem détail du quota offert par une activité (champs officiels : capabilities / effective_at / priorité par élément)
type GrantItem struct {
	Name         string   `json:"name"`
	Units        float64  `json:"units"`
	Period       string   `json:"period"` // one_time | daily | weekly | monthly
	Priority     int      `json:"priority,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	EffectiveAt  int64    `json:"effective_at,omitempty"` // secondes epoch (effective_at officiel)
}

// ActivityPlan activité réclamable
type ActivityPlan struct {
	PlanID      string      `json:"plan_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Priority    int         `json:"priority"`
	Grants      []string    `json:"grants"`
	GrantItems  []GrantItem `json:"grant_items"`
}

// ClaimedPlan détail du forfait renvoyé par le serveur après une réclamation réussie (data.plan officiel)
type ClaimedPlan struct {
	UserPlanID string `json:"user_plan_id"`
	PlanID     string `json:"plan_id"`
	Status     string `json:"status"`
	StartsAt   int64  `json:"starts_at,omitempty"` // secondes epoch
	EndsAt     int64  `json:"ends_at,omitempty"`   // secondes epoch
}

// ClaimResult résultat de la réclamation
type ClaimResult struct {
	OK         bool         `json:"ok"`
	Code       int          `json:"code"`
	Message    string       `json:"message"`
	PlanID     string       `json:"plan_id"`
	PlanName   string       `json:"plan_name"`
	NextAt     int64        `json:"next_at"`      // prochaine réclamation possible en millisecondes epoch (cas 1005)
	ServerTime int64        `json:"server_time"`  // data.server_time officiel (millisecondes)
	Plan       *ClaimedPlan `json:"plan,omitempty"`
}

// claimFailMessages code d'erreur métier → libellé affiché (aligné sur l'i18n de zcode-switch)
var claimFailMessages = map[int]string{
	1001: "Forfait introuvable",
	1002: "Activité terminée ou forfait temporairement non réclamable",
	1003: "Ce forfait a déjà été réclamé",
	1004: "Conditions de réclamation non remplies",
	1005: "Quota de réclamations du jour épuisé",
	3001: "Paramètres de réclamation invalides, actualisez puis réessayez",
	3007: "Échec de validation du captcha, réessayez",
	401:  "Connectez-vous avant de réclamer",
}

func claimFailureMessage(code int, body map[string]interface{}) string {
	base, ok := claimFailMessages[code]
	if !ok {
		base = "Échec de la réclamation"
	}
	serverMsg := ""
	if body != nil {
		serverMsg = firstNonEmpty(jsonStr(body, "msg"), jsonStr(body, "message"))
	}
	if serverMsg != "" {
		return fmt.Sprintf("%s (%s)", base, serverMsg)
	}
	return base
}

// PreviewPlans détecte la liste des activités actuellement récupérables (par ordre décroissant de priorité)
func (z *ZCodeAPI) PreviewPlans(a *Account) ([]ActivityPlan, error) {
	token := z.billingToken(a)
	if token == "" {
		return nil, fmt.Errorf("Le compte n'a pas d'identifiant JWT, détection des activités impossible")
	}
	urlStr := fmt.Sprintf("%s?app_version=%s&platform=%s", BillingPreviewURL, z.appVersion, ClientPlatform())
	resp, err := z.doGetJSON(a, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("Échec de la requête d'aperçu des activités : %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("Échec d'authentification HTTP %d (identifiants peut-être expirés)", resp.StatusCode)
	}
	if resp.Body == nil {
		return nil, fmt.Errorf("Échec d'analyse de la réponse d'aperçu des activités : %s", truncate(resp.RawText, 200))
	}
	if code := jsonInt(resp.Body, "code"); code != 0 {
		return nil, fmt.Errorf("Échec de l'aperçu des activités : %s", claimFailureMessage(code, resp.Body))
	}
	data, _ := resp.Body["data"].(map[string]interface{})
	if data == nil {
		return nil, nil
	}
	plansRaw, _ := data["plans"].([]interface{})
	var out []ActivityPlan
	for _, p := range plansRaw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if ap := parseActivityPlan(pm); ap != nil {
			out = append(out, *ap)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].PlanID < out[j].PlanID
	})
	return out, nil
}

func parseActivityPlan(p map[string]interface{}) *ActivityPlan {
	planID := strings.TrimSpace(firstNonEmpty(jsonStr(p, "plan_id"), jsonStr(p, "planId")))
	if planID == "" {
		return nil
	}
	ap := &ActivityPlan{
		PlanID:      planID,
		Name:        strings.TrimSpace(jsonStr(p, "name")),
		Description: strings.TrimSpace(jsonStr(p, "description")),
		Priority:    jsonInt(p, "priority"),
	}
	if ap.Priority < 0 {
		ap.Priority = 0
	}
	// entitlements[] → ne conserve que les éléments offerts de type model_usage/token
	if ents, ok := p["entitlements"].([]interface{}); ok {
		for _, e := range ents {
			em, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			meter := firstNonEmpty(jsonStr(em, "meter"))
			unitType := firstNonEmpty(jsonStr(em, "unit_type"), jsonStr(em, "unitType"))
			showName := strings.TrimSpace(firstNonEmpty(jsonStr(em, "show_name"), jsonStr(em, "showName")))
			if meter != "model_usage" || unitType != "token" || showName == "" {
				continue
			}
			units := 0.0
			if n := jsonNum(em, "grant_units", "grantUnits"); n != nil {
				units = *n
			}
			period := firstNonEmpty(jsonStr(em, "period"), "one_time")
			gi := GrantItem{Name: showName, Units: units, Period: period, Priority: jsonInt(em, "priority")}
			// champs supplémentaires officiels : capabilities[], effective_at
			if caps, ok := em["capabilities"].([]interface{}); ok {
				for _, c := range caps {
					if cs, ok := c.(string); ok && cs != "" {
						gi.Capabilities = append(gi.Capabilities, cs)
					}
				}
			}
			if ea := jsonNum(em, "effective_at", "effectiveAt"); ea != nil {
				gi.EffectiveAt = int64(*ea)
			}
			ap.GrantItems = append(ap.GrantItems, gi)
			ap.Grants = append(ap.Grants, fmt.Sprintf("%s · %s Token (%s)", showName, formatUnits(units), periodLabelCN(period)))
		}
	}
	return ap
}

func periodLabelCN(period string) string {
	switch period {
	case "daily":
		return "Quotidien"
	case "weekly":
		return "Hebdomadaire"
	case "monthly":
		return "Mensuel"
	}
	return "Unique"
}

// formatUnits abréviation des grandes valeurs (portage de fmt_units de claim.rs)
func formatUnits(n float64) string {
	trim := func(x float64) string {
		r := math_Round(x*10) / 10
		if r == float64(int64(r)) {
			return fmt.Sprintf("%d", int64(r))
		}
		return fmt.Sprintf("%.1f", r)
	}
	switch {
	case n >= 1e8:
		return trim(n/1e8) + " ×10⁸"
	case n >= 1e4:
		return trim(n/1e4) + " ×10⁴"
	}
	return fmt.Sprintf("%d", int64(math_Round(n)))
}

func math_Round(x float64) float64 {
	if x < 0 {
		return -float64(int64(-x+0.5))
	}
	return float64(int64(x + 0.5))
}

// SubmitClaim soumet la réclamation (paramètre de captcha obligatoire)
func (z *ZCodeAPI) SubmitClaim(a *Account, planID, captchaParam, captchaRegion string) *ClaimResult {
	result := &ClaimResult{PlanID: planID}
	if strings.TrimSpace(captchaParam) == "" {
		result.Code = -1
		result.Message = "Paramètre de vérification anti-robot manquant (échec de résolution du captcha)"
		return result
	}
	token := z.billingToken(a)
	if token == "" {
		result.Code = -1
		result.Message = "Le compte n'a pas d'identifiant JWT"
		return result
	}

	body, _ := json.Marshal(map[string]string{"plan_id": planID})
	client := ClientForURL(z.egress.ProxyURLForAccount(a), BillingClaimURL, 25*time.Second)
	req, err := http.NewRequest("POST", BillingClaimURL, bytes.NewReader(body))
	if err != nil {
		result.Code = -1
		result.Message = err.Error()
		return result
	}
	id := NewClientIdentity(z.appVersion, a.DeviceMid)
	for k, v := range ZaiClientHeaders(id) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Aliyun-Captcha-Verify-Param", strings.TrimSpace(captchaParam))
	if r := strings.TrimSpace(captchaRegion); r != "" {
		req.Header.Set("X-Aliyun-Captcha-Verify-Region", r)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Code = -1
		result.Message = fmt.Sprintf("Échec de la requête de réclamation : %v", err)
		return result
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var v map[string]interface{}
	json.Unmarshal(raw, &v)

	code := jsonInt(v, "code")
	if resp.StatusCode >= 400 && code == -1 {
		code = resp.StatusCode
	}
	result.Code = code
	// data.server_time officiel (secondes → millisecondes)
	if data, ok := v["data"].(map[string]interface{}); ok {
		if st := jsonNum(data, "server_time"); st != nil {
			result.ServerTime = int64(*st) * 1000
		}
	}
	if code == 0 {
		result.OK = true
		result.Message = "Réclamation réussie"
		// data.plan officiel : {user_plan_id, plan_id, status, starts_at, ends_at}
		if data, ok := v["data"].(map[string]interface{}); ok {
			if plan, ok := data["plan"].(map[string]interface{}); ok {
				cp := &ClaimedPlan{
					UserPlanID: jsonStr(plan, "user_plan_id"),
					PlanID:     firstNonEmpty(jsonStr(plan, "plan_id"), planID),
					Status:     jsonStr(plan, "status"),
				}
				if n := jsonNum(plan, "starts_at"); n != nil {
					cp.StartsAt = int64(*n)
				}
				if n := jsonNum(plan, "ends_at"); n != nil {
					cp.EndsAt = int64(*n)
				}
				result.Plan = cp
				result.PlanName = firstNonEmpty(jsonStr(plan, "name"), cp.PlanID)
			}
		}
		if result.PlanName == "" {
			result.PlanName = planID
		}
		return result
	}
	result.Message = claimFailureMessage(code, v)
	// 1005 : quota du jour épuisé, extraction de la prochaine réclamation possible (failureEndsAt officiel = data.plan.ends_at en secondes)
	if code == 1005 {
		if data, ok := v["data"].(map[string]interface{}); ok {
			if plan, ok := data["plan"].(map[string]interface{}); ok {
				if ends := jsonNum(plan, "ends_at"); ends != nil && *ends > 0 {
					result.NextAt = int64(*ends) * 1000
				}
			}
		}
	}
	return result
}

// ReportActivation envoie les événements d'activation (app_launch + app_daily_active) et déclenche l'attribution du Start Plan côté serveur
func (z *ZCodeAPI) ReportActivation(a *Account) error {
	userID := z.telemetryUserID(a)
	if userID == "" {
		return fmt.Errorf("Impossible de déterminer le user_id (user_info absent)")
	}
	mid := a.DeviceMid
	if mid == "" {
		mid = LocalDeviceMid()
	}
	client := ClientForURL(z.egress.ProxyURLForAccount(a), EventReportURL, 15*time.Second)
	for _, element := range []string{"app_launch", "app_daily_active"} {
		payload := map[string]interface{}{
			"event_id":            uuid.NewString(),
			"client_timezone":     clientTimezoneValue(),
			"client_language":     zcodeLang,
			"element_name":        element,
			"event_region":        "app",
			"event_type":          "view",
			"event_text":          "",
			"event_extra_detail":  map[string]interface{}{},
			"user_id":             userID,
			"screen_resolution":   screenResolution,
			"app_version":         z.appVersion,
			"device_os_category":  osCategoryValue(),
			"device_os_version":   cachedOSVer,
			"device_mid":          mid,
			"mac_id":              "",
			"marketing_params":    "{}",
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", EventReportURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		id := NewClientIdentity(z.appVersion, mid)
		for k, v := range ZaiClientHeaders(id) {
			req.Header.Set(k, v)
		}
		if token := z.billingToken(a); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("Échec de l'envoi de l'événement d'activation %s : %w", element, err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var v map[string]interface{}
		json.Unmarshal(raw, &v)
		if code := jsonInt(v, "code"); code != 0 && code != -1 {
			return fmt.Errorf("Événement d'activation %s refusé : %s", element, claimFailureMessage(code, v))
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("Événement d'activation %s HTTP %d : %s", element, resp.StatusCode, truncate(string(raw), 150))
		}
	}
	return nil
}

// telemetryUserID extrait user_id depuis user_info (portage de telemetry_user_id de claim.rs)
func (z *ZCodeAPI) telemetryUserID(a *Account) string {
	if a.UserInfo != "" {
		var ui map[string]interface{}
		if json.Unmarshal([]byte(a.UserInfo), &ui) == nil {
			if id := firstNonEmpty(jsonStr(ui, "id"), jsonStr(ui, "user_id")); id != "" {
				return id
			}
		}
	}
	// Repli : décodage du payload JWT de access_token / zcode_jwt
	for _, tok := range []string{a.AccessToken, a.ZCodeJWT} {
		if tok == "" {
			continue
		}
		if claims, err := DecodeJWTPayload(tok); err == nil {
			if id := firstNonEmpty(jsonStr(claims, "user_id"), jsonStr(claims, "sub")); id != "" {
				return id
			}
		}
	}
	return a.UserID
}

// ClaimForAccount flux combiné : détection des activités → sélection de la priorité la plus haute → résolution du captcha → réclamation → enregistrement.
// Exclusion mutuelle par compte : le client officiel utilise un verrou diffusé entre fenêtres pour éviter les réclamations en double (createBroadcastService) ;
// ici un mutex par compte produit le même effet (pas de double réclamation entre l'UI manuelle et le planificateur cron).
func (z *ZCodeAPI) ClaimForAccount(a *Account) *ClaimResult {
	mu := z.claimLockFor(a.ID)
	if !mu.TryLock() {
		return &ClaimResult{Code: -1, Message: "Une tâche de réclamation est déjà en cours pour ce compte (exclusion mutuelle locale)"}
	}
	defer mu.Unlock()
	return z.claimForAccountLocked(a)
}

func (z *ZCodeAPI) claimLockFor(id int64) *sync.Mutex {
	z.claimMu.Lock()
	defer z.claimMu.Unlock()
	if m, ok := z.claimLocks[id]; ok {
		return m
	}
	m := &sync.Mutex{}
	z.claimLocks[id] = m
	return m
}

func (z *ZCodeAPI) claimForAccountLocked(a *Account) *ClaimResult {
	plans, err := z.PreviewPlans(a)
	record := &ClaimRecord{AccountID: a.ID, Email: a.Email, TaskType: "claim"}
	if err != nil {
		record.Success = false
		record.Message = err.Error()
		z.db.InsertClaimRecord(record)
		return &ClaimResult{Code: -1, Message: err.Error()}
	}
	if len(plans) == 0 {
		// Aucune activité est traité comme une exécution réussie à vide (cohérent avec detect, évite un faux failed dans les statistiques 0/N)
		record.Success = true
		record.Message = "Aucune activité à réclamer pour le moment"
		z.db.InsertClaimRecord(record)
		return &ClaimResult{OK: true, Code: 0, Message: "Aucune activité à réclamer pour le moment"}
	}
	plan := plans[0] // Déjà trié par priorité décroissante
	record.PlanID = plan.PlanID
	record.PlanName = plan.Name

	// Résolution du captcha Aliyun
	captchaParam, region, err := z.captcha.GetVerifyParam(a)
	if err != nil {
		record.Message = fmt.Sprintf("Échec de résolution du captcha : %v", err)
		z.db.InsertClaimRecord(record)
		z.db.SetAccountClaimResult(a.ID, plan.Name, record.Message)
		return &ClaimResult{Code: -1, PlanID: plan.PlanID, PlanName: plan.Name, Message: record.Message}
	}

	result := z.SubmitClaim(a, plan.PlanID, captchaParam, region)
	result.PlanName = firstNonEmpty(result.PlanName, plan.Name)
	record.Success = result.OK
	record.Code = result.Code
	record.Message = result.Message
	record.NextAt = result.NextAt
	z.db.InsertClaimRecord(record)
	z.db.SetAccountClaimResult(a.ID, result.PlanName, result.Message)

	// Rafraîchissement asynchrone du quota après une réclamation réussie
	if result.OK {
		go func() {
			time.Sleep(2 * time.Second)
			z.RefreshAccountQuota(a)
		}()
	}
	return result
}

// DetectForAccount détecte uniquement les activités (sans réclamer)
func (z *ZCodeAPI) DetectForAccount(a *Account) *ClaimResult {
	plans, err := z.PreviewPlans(a)
	record := &ClaimRecord{AccountID: a.ID, Email: a.Email, TaskType: "detect"}
	if err != nil {
		record.Message = err.Error()
		z.db.InsertClaimRecord(record)
		return &ClaimResult{Code: -1, Message: err.Error()}
	}
	if len(plans) == 0 {
		record.Success = true
		record.Message = "Aucune activité à réclamer"
		z.db.InsertClaimRecord(record)
		return &ClaimResult{OK: true, Message: "Aucune activité à réclamer"}
	}
	names := make([]string, 0, len(plans))
	for _, p := range plans {
		names = append(names, p.Name)
	}
	record.Success = true
	record.PlanID = plans[0].PlanID
	record.PlanName = strings.Join(names, ", ")
	record.Message = fmt.Sprintf("%d activités détectées : %s", len(plans), record.PlanName)
	z.db.InsertClaimRecord(record)
	return &ClaimResult{OK: true, PlanID: plans[0].PlanID, PlanName: record.PlanName, Message: record.Message}
}

// ActivateForAccount flux d'activation : envoi des événements d'activation → rafraîchissement du quota pour confirmer l'activation du forfait
func (z *ZCodeAPI) ActivateForAccount(a *Account) *ClaimResult {
	record := &ClaimRecord{AccountID: a.ID, Email: a.Email, TaskType: "activate"}
	if err := z.ReportActivation(a); err != nil {
		record.Message = err.Error()
		z.db.InsertClaimRecord(record)
		return &ClaimResult{Code: -1, Message: err.Error()}
	}
	// Rafraîchissement du quota après l'envoi, pour confirmation
	time.Sleep(1500 * time.Millisecond)
	ov, err := z.FetchQuotaRaw(a)
	if err != nil {
		record.Success = true
		record.Message = "Événements d'activation envoyés ; échec de confirmation du quota : " + err.Error()
		z.db.InsertClaimRecord(record)
		return &ClaimResult{OK: true, Message: record.Message}
	}
	z.applyQuotaResult(a, ov)
	if ov.PlanTier != "" {
		record.Success = true
		record.PlanName = ov.PlanTier
		record.Message = fmt.Sprintf("Activation réussie, forfait actuel : %s", ov.PlanTier)
	} else {
		record.Message = "Événements d'activation envoyés, mais aucun forfait actif détecté (attribution serveur peut-être différée)"
	}
	z.db.InsertClaimRecord(record)
	return &ClaimResult{OK: record.Success, PlanName: ov.PlanTier, Message: record.Message}
}

// truncate tronque par rune pour ne pas couper les caractères UTF-8 multi-octets
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
