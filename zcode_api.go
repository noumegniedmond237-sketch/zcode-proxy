package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- Wrapper de l'API amont ZCode ----
// Gère le pool de comptes / le service captcha / le proxy de sortie, et fournit l'actualisation des quotas, la récupération des offres et le relais des requêtes.

type ZCodeAPI struct {
	cfg        *FileConfig
	db         *DB
	pool       *AccountPool
	captcha    *CaptchaService
	egress     *EgressProxy
	appVersion string

	claimMu    sync.Mutex
	claimLocks map[int64]*sync.Mutex // Mutex par compte pour la réclamation (évite la double réclamation concurrentielle UI + cron)
}

// NewZCodeAPI crée le wrapper de l'API amont et injecte la fonction de rafraîchissement des quotas dans le pool de comptes
func NewZCodeAPI(cfg *FileConfig, db *DB, pool *AccountPool, captcha *CaptchaService, appVersion string) *ZCodeAPI {
	z := &ZCodeAPI{
		cfg:        cfg,
		db:         db,
		pool:       pool,
		captcha:    captcha,
		egress:     NewEgressProxy(db),
		appVersion: appVersion,
		claimLocks: make(map[int64]*sync.Mutex),
	}
	pool.SetQuotaFetcher(z.RefreshAccountQuota)
	return z
}

// RefreshAccountQuota récupère le quota -> applique la transition d'état -> enregistre en base
func (z *ZCodeAPI) RefreshAccountQuota(a *Account) error {
	ov, err := z.FetchQuotaRaw(a)
	if err != nil {
		return err
	}
	z.applyQuotaResult(a, ov)
	return nil
}

// applyQuotaResult pilote la machine d'état selon le résultat du quota (portage de la transition d'état de quota.py)
func (z *ZCodeAPI) applyQuotaResult(a *Account, ov *QuotaOverview) {
	switch {
	case ov.AuthFailed:
		z.pool.MarkInvalid(a, "Échec d'authentification sur l'API de quota (401/403), identifiants peut-être expirés")
		return
	case ov.NotEntitled:
		z.pool.MarkInactive(a, "Coding Plan non activé (aucun abonnement éligible)")
		return
	case ov.AllExhausted():
		z.pool.MarkExhausted(a, "Quota épuisé")
	default:
		// S'il reste du quota : cooling expiré / exhausted / inactive / invalid redevient active
		if a.Status == StatusExhausted || a.Status == StatusInactive || a.Status == StatusInvalid ||
			(a.Status == StatusCooling && (a.CoolingUntil <= 0 || time.Now().Unix() >= a.CoolingUntil)) {
			a.Status = StatusActive
			a.CoolingUntil = 0
			a.LastError = ""
			z.db.SetAccountStatus(a.ID, StatusActive, "", 0)
			log.Printf("[quota] account %s recovered -> active", a.Email)
		}
	}

	// Persistance de l'instantané de quota
	quotaJSON, _ := json.Marshal(ov)
	total, used, remaining := 0.0, 0.0, 0.0
	if ov.Total != nil {
		total = *ov.Total
	}
	if ov.Used != nil {
		used = *ov.Used
	}
	if ov.Remaining != nil {
		remaining = *ov.Remaining
	}
	a.QuotaJSON = string(quotaJSON)
	a.PlanTier = ov.PlanTier
	a.PlanExpire = ov.PlanExpire
	a.TotalUnits = total
	a.UsedUnits = used
	a.Remaining = remaining
	a.LastCheckedAt = time.Now().Unix()
	if err := z.db.SetAccountQuota(a.ID, string(quotaJSON), ov.PlanTier, ov.PlanExpire, total, used, remaining); err != nil {
		log.Printf("[quota] persist %s: %v", a.Email, err)
	}
}

// HandleCountTokens POST /v1/messages/count_tokens — sondé par le SDK Anthropic.
// La passerelle renvoie une estimation prudente (nb caractères/4 + overhead) pour éviter une erreur 405.
func (z *ZCodeAPI) HandleCountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Messages json.RawMessage `json:"messages"`
		System   json.RawMessage `json:"system"`
		Tools    json.RawMessage `json:"tools"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	chars := len(body.Messages) + len(body.System) + len(body.Tools)
	est := chars/4 + 8
	writeJSON(w, http.StatusOK, map[string]interface{}{"input_tokens": est})
}

// HandleModels GET /v1/models — compatible simultanément avec les champs OpenAI et Anthropic
func (z *ZCodeAPI) HandleModels(w http.ResponseWriter, r *http.Request) {
	models := z.cfg.GetModels()
	// La configuration en base peut surcharger la liste des modèles
	if extra, _ := z.db.GetSetting("gateway_models"); strings.TrimSpace(extra) != "" {
		var list []string
		for _, m := range strings.Split(extra, ",") {
			if m = strings.TrimSpace(m); m != "" {
				list = append(list, m)
			}
		}
		if len(list) > 0 {
			models = list
		}
	}
	now := time.Now().Unix()
	data := make([]map[string]interface{}, 0, len(models))
	for _, m := range models {
		data = append(data, map[string]interface{}{
			"id":           m,
			"object":       "model", // Champ validé par les clients OpenAI
			"type":         "model", // Champ validé par les clients Anthropic
			"display_name": m,
			"created":      now,
			"created_at":   "2025-01-01T00:00:00Z",
			"owned_by":     "zcode-proxy",
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"object": "list", "data": data})
}
