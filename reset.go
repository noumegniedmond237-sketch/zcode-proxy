package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ---- Réinitialisation manuelle du quota Coding Plan (découverte par audit app.asar) ----
// base = zcode.z.ai ; accessible uniquement aux comptes Coding Plan payants (Start Plan renvoie 3101).
// Permet de consommer une opportunité de « réinitialisation de fenêtre 5h » ou « réinitialisation hebdo » pour restaurer le quota.
// En-têtes de requête (portage de createCodingPlanResetHeaders) :
//   Authorization: Bearer <zcodejwttoken>
//   X-Bigmodel-Authorization: <coding-plan apiKey>
//   Bigmodel-Target-Type: PERSONAL | TEAM (avec Organization/Project en mode TEAM)

const CodingPlanResetBase = "https://zcode.z.ai/api/v1/coding-plan/reset"

// ResetSlot créneau d'opportunité de réinitialisation
type ResetSlot struct {
	ExpireAt int64 `json:"expire_at"`
}

// ResetUsed historique d'utilisation de réinitialisation
type ResetUsed struct {
	UsedAt int64 `json:"used_at"`
}

// ResetStatus état des réinitialisations
type ResetStatus struct {
	AvailableFiveHourResets  []ResetSlot `json:"available_five_hour_resets"`
	AvailableWeekResets      []ResetSlot `json:"available_week_resets"`
	LatestFiveHourReset      *ResetUsed  `json:"latest_five_hour_reset_history"`
	LatestWeekReset          *ResetUsed  `json:"latest_week_reset_history"`
	HasUnreadHistory         bool        `json:"has_unread_history"`
}

// resetHeaders portage de AC() : double identifiant + contexte d'équipe
func (z *ZCodeAPI) resetHeaders(a *Account) map[string]string {
	h := map[string]string{
		"Authorization": "Bearer " + a.ZCodeJWT,
		"User-Agent":    "ZCode/" + z.appVersion,
		"accept":        "application/json",
	}
	if a.APIKey != "" {
		h["X-Bigmodel-Authorization"] = a.APIKey
	}
	// Contexte d'équipe : activé lorsque la note ou le groupe du compte est au format team:orgId:projId
	if org, proj, ok := parseTeamContext(a); ok {
		h["Bigmodel-Target-Type"] = "TEAM"
		h["Bigmodel-Organization"] = org
		h["Bigmodel-Project"] = proj
	} else {
		h["Bigmodel-Target-Type"] = "PERSONAL"
	}
	return h
}

// parseTeamContext extrait team:<orgId>:<projId> depuis la note du compte
func parseTeamContext(a *Account) (org, proj string, ok bool) {
	var t struct {
		Team struct {
			Org  string `json:"org"`
			Proj string `json:"proj"`
		} `json:"team"`
	}
	if a.Remark != "" && json.Unmarshal([]byte(a.Remark), &t) == nil && t.Team.Org != "" && t.Team.Proj != "" {
		return t.Team.Org, t.Team.Proj, true
	}
	return "", "", false
}

func (z *ZCodeAPI) resetRequest(a *Account, method, path string, body map[string]interface{}) (map[string]interface{}, int, error) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	urlStr := CodingPlanResetBase + path
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range z.resetHeaders(a) {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	client := ClientForURL(z.egress.ProxyURLForAccount(a), urlStr, 15*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var v map[string]interface{}
	json.Unmarshal(raw, &v)
	return v, resp.StatusCode, nil
}

// FetchResetStatus GET reset/status
func (z *ZCodeAPI) FetchResetStatus(a *Account) (*ResetStatus, int, string, error) {
	if a.ZCodeJWT == "" {
		return nil, 0, "", fmt.Errorf("JWT ZCode requis")
	}
	v, status, err := z.resetRequest(a, "GET", "/status", nil)
	if err != nil {
		return nil, status, "", err
	}
	code := jsonInt(v, "code")
	if code != 0 {
		return nil, status, firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message")), fmt.Errorf("Code métier %d : %s", code, firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message")))
	}
	data, _ := v["data"].(map[string]interface{})
	if data == nil {
		return nil, status, "", fmt.Errorf("data manquant dans la réponse")
	}
	raw, _ := json.Marshal(data)
	var st ResetStatus
	json.Unmarshal(raw, &st)
	return &st, status, "", nil
}

// UseReset POST reset/use {idempotency_key, reset_type}
func (z *ZCodeAPI) UseReset(a *Account, resetType string) (bool, int64, string, error) {
	idem := uuid.NewString()
	v, _, err := z.resetRequest(a, "POST", "/use", map[string]interface{}{
		"idempotency_key": idem,
		"reset_type":      resetType,
	})
	if err != nil {
		return false, 0, "", err
	}
	code := jsonInt(v, "code")
	msg := firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message"))
	if code != 0 {
		return false, 0, msg, fmt.Errorf("Code métier %d : %s", code, msg)
	}
	data, _ := v["data"].(map[string]interface{})
	used := false
	if d, ok := data["used"].(bool); ok {
		used = d
	}
	return used, 0, msg, nil
}

// RequestResetOpportunity POST reset/opportunity (3301 = opportunité accordée)
func (z *ZCodeAPI) RequestResetOpportunity(a *Account) (granted bool, nextTry int64, msg string, err error) {
	idem := uuid.NewString()
	v, status, err := z.resetRequest(a, "POST", "/opportunity", map[string]interface{}{
		"idempotency_key": idem,
	})
	if err != nil {
		return false, 0, "", err
	}
	if status == 429 {
		return false, 0, "Demande d'opportunité de réinitialisation limitée", fmt.Errorf("HTTP 429 throttled")
	}
	code := jsonInt(v, "code")
	data, _ := v["data"].(map[string]interface{})
	if d, ok := data["granted"].(bool); ok && d {
		return true, 0, firstNonEmpty(jsonStr(v, "msg"), "Opportunité accordée"), nil
	}
	if d, ok := data["granted"].(bool); ok && !d {
		if n := jsonNum(data, "next_try_at"); n != nil {
			return false, int64(*n) * 1000, "Opportunité non accordée", nil
		}
		return false, 0, "Opportunité non accordée", nil
	}
	if code == 3301 {
		return true, 0, "Opportunité accordée (3301)", nil
	}
	return false, 0, firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message")), fmt.Errorf("Code métier %d", code)
}

// ResetForAccount flux combiné : état -> five_hour en priorité sinon week -> use -> actualisation quota -> enregistrement.
// Mutex par compte : empêche la double consommation en cas de concurrence manuel + cron.
func (z *ZCodeAPI) ResetForAccount(a *Account) *ClaimResult {
	mu := z.claimLockFor(a.ID)
	if !mu.TryLock() {
		return &ClaimResult{Code: -1, Message: "Une tâche de récupération/réinitialisation est déjà en cours sur ce compte"}
	}
	defer mu.Unlock()
	return z.resetForAccountLocked(a)
}

func (z *ZCodeAPI) resetForAccountLocked(a *Account) *ClaimResult {
	record := &ClaimRecord{AccountID: a.ID, Email: a.Email, TaskType: "reset"}
	st, _, bizMsg, err := z.FetchResetStatus(a)
	if err != nil {
		record.Message = fmt.Sprintf("Échec de requête du statut de réinitialisation : %v", err)
		if bizMsg != "" {
			record.Message = bizMsg
		}
		z.db.InsertClaimRecord(record)
		return &ClaimResult{Code: -1, Message: record.Message}
	}
	resetType := ""
	switch {
	case len(st.AvailableFiveHourResets) > 0:
		resetType = "five_hour"
	case len(st.AvailableWeekResets) > 0:
		resetType = "week"
	}
	if resetType == "" {
		record.Success = true
		record.Message = "Aucune opportunité de réinitialisation disponible (5h/hebdo épuisées)"
		z.db.InsertClaimRecord(record)
		return &ClaimResult{OK: true, Message: record.Message}
	}
	used, _, msg, err := z.UseReset(a, resetType)
	if err != nil || !used {
		record.Message = fmt.Sprintf("Échec d'exécution de la réinitialisation (%s) : %v %s", resetType, err, msg)
		z.db.InsertClaimRecord(record)
		z.db.SetAccountClaimResult(a.ID, "Réinitialisation du quota", record.Message)
		return &ClaimResult{Code: -1, Message: record.Message}
	}
	record.Success = true
	record.PlanName = "Réinitialisation du quota (" + resetType + ")"
	record.Message = "Réinitialisation réussie, quota restauré"
	z.db.InsertClaimRecord(record)
	z.db.SetAccountClaimResult(a.ID, record.PlanName, record.Message)
	log.Printf("[reset] account %s quota reset via %s", a.Email, resetType)
	go func() {
		time.Sleep(2 * time.Second)
		z.RefreshAccountQuota(a)
	}()
	return &ClaimResult{OK: true, PlanName: record.PlanName, Message: record.Message}
}

// ---- Synchronisation du catalogue officiel de modèles (client/configs) ----

// CatalogModel modèle du catalogue
type CatalogModel struct {
	ModelID       string `json:"modelId"`
	Name          string `json:"name"`
	ContextWindow int    `json:"contextWindow"`
	Priority      int    `json:"priority"`
	Vision        bool   `json:"vision"`
}

// SyncModelCatalog récupère le catalogue officiel (builtinModels) et rafraîchit le cache captcha
func (z *ZCodeAPI) SyncModelCatalog() ([]CatalogModel, error) {
	urlStr := fmt.Sprintf("%s?version=%s&os=%s", ClientConfigsURL, z.appVersion, NodePlatform())
	client := ClientForURL("", urlStr, 20*time.Second)
	req, _ := http.NewRequest("GET", urlStr, nil)
	id := NewClientIdentity(z.appVersion, "")
	for k, v := range ZaiClientHeaders(id) {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var v struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			BuiltinModels []CatalogModel `json:"builtinModels"`
			Providers     []struct {
				ID      string `json:"id"`
				BaseURL string `json:"baseUrl"`
				Models  []CatalogModel `json:"models"`
			} `json:"providers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("Échec d'analyse du catalogue : %w", err)
	}
	if v.Code != 0 {
		return nil, fmt.Errorf("Code métier %d : %s", v.Code, v.Msg)
	}
	models := v.Data.BuiltinModels
	if len(models) == 0 {
		for _, p := range v.Data.Providers {
			models = append(models, p.Models...)
		}
	}
	// Mise en cache et déduplication
	seen := map[string]bool{}
	var uniq []CatalogModel
	for _, m := range models {
		if m.ModelID == "" || seen[m.ModelID] {
			continue
		}
		seen[m.ModelID] = true
		uniq = append(uniq, m)
	}
	if cj, err := json.Marshal(uniq); err == nil {
		z.db.SetSetting("model_catalog", string(cj))
	}
	log.Printf("[catalog] synced %d models from client/configs", len(uniq))
	return uniq, nil
}

// GetModelCatalog lit le catalogue en cache
func (z *ZCodeAPI) GetModelCatalog() []CatalogModel {
func (z *ZCodeAPI) GetModelCatalog() []CatalogModel {
	raw, _ := z.db.GetSetting("model_catalog")
	if raw == "" {
		return nil
	}
	var out []CatalogModel
	json.Unmarshal([]byte(raw), &out)
	return out
}
