package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- Requête et normalisation de quota ----
// Deux canaux :
//   jwt    → zcode.z.ai /api/v1/zcode-plan/billing/current (puis /billing/balance en cas d'échec)
//   apikey → api.z.ai /api/monitor/usage/quota/limit + /api/biz/subscription/list
// Normalisation portée depuis zcode-switch quota.rs (structures plans/balances + alias de champs défensifs).

const (
	BillingBaseURL     = "https://zcode.z.ai/api/v1/zcode-plan"
	SubscriptionURL    = "https://api.z.ai/api/biz/subscription/list"
	QuotaLimitURL      = "https://api.z.ai/api/monitor/usage/quota/limit"
	BillingPreviewURL  = "https://zcode.z.ai/api/v1/zcode-plan/billing/preview"
	BillingClaimURL    = "https://zcode.z.ai/api/v1/zcode-plan/billing/claim"
	EventReportURL     = "https://zcode.z.ai/api/v1/event/report"
	ClientConfigsURL   = "https://zcode.z.ai/api/v1/client/configs"
)

// QuotaItem fragment de quota unitaire
type QuotaItem struct {
	Name        string   `json:"name"`
	Total       *float64 `json:"total"`
	Used        *float64 `json:"used"`
	Remaining   *float64 `json:"remaining"`
	PercentUsed *float64 `json:"percent_used"`
	Unit        string   `json:"unit"`
	PeriodEnd   string   `json:"period_end"`
}

// QuotaOverview vue d'ensemble normalisée du quota
// QuotaPlanSlot emplacement de forfait individuel (plans[] et ses balances détaillées)
type QuotaPlanSlot struct {
	PlanID      string      `json:"plan_id"`
	Name        string      `json:"name"`
	Tier        string      `json:"tier"`
	Status      string      `json:"status"`
	Expire      string      `json:"expire"`
	Total       *float64    `json:"total"`
	Used        *float64    `json:"used"`
	Remaining   *float64    `json:"remaining"`
	PercentUsed *float64    `json:"percent_used"`
	Items       []QuotaItem `json:"items"`
}

type QuotaOverview struct {
	PlanTier    string          `json:"plan_tier"`
	PlanExpire  string          `json:"plan_expire"`
	Total       *float64        `json:"total"`
	Used        *float64        `json:"used"`
	Remaining   *float64        `json:"remaining"`
	PercentUsed *float64        `json:"percent_used"`
	Items       []QuotaItem     `json:"items"`
	Plans       []QuotaPlanSlot `json:"plans"`
	Source      string          `json:"source"`
	RefreshedAt int64           `json:"refreshed_at"`
	NotEntitled bool            `json:"not_entitled"` // Sans Coding Plan / inactif
	AuthFailed  bool            `json:"auth_failed"`  // Identifiants 401/403 invalides
	IsEmpty     bool            `json:"is_empty"`
}

// apiResponse interne : HTTP + code métier + JSON brut
type apiResponse struct {
	StatusCode int
	Body       map[string]interface{}
	RawText    string
}

// doGetJSON requête GET avec en-têtes d'identité client
func (z *ZCodeAPI) doGetJSON(a *Account, urlStr string, extraHeaders map[string]string) (*apiResponse, error) {
	client := ClientForURL(z.egress.ProxyURLForAccount(a), urlStr, 25*time.Second)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	id := NewClientIdentity(z.appVersion, a.DeviceMid)
	for k, v := range ZaiClientHeaders(id) {
		req.Header.Set(k, v)
	}
	// Authentification : JWT en priorité, le canal API Key passe aussi par Bearer
	token := z.billingToken(a)
	if token == "" {
		return nil, fmt.Errorf("Compte sans identifiant valide")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	out := &apiResponse{StatusCode: resp.StatusCode, RawText: string(body)}
	if len(body) > 0 {
		var v map[string]interface{}
		if json.Unmarshal(body, &v) == nil {
			out.Body = v
		}
	}
	return out, nil
}

// billingToken sélectionne l'identifiant pour l'interface de facturation :
// zcode_jwt pour compte JWT ; api_key pour compte API Key
func (z *ZCodeAPI) billingToken(a *Account) string {
	if a.ZCodeJWT != "" {
		return a.ZCodeJWT
	}
	return a.APIKey
}

func businessOK(v map[string]interface{}) bool {
	if v == nil {
		return false
	}
	if success, ok := v["success"].(bool); ok && !success {
		return false
	}
	if _, has := v["code"]; !has {
		return true
	}
	n := jsonInt(v, "code")
	return n == 0 || n == 200
}

func jsonInt(v map[string]interface{}, key string) int {
	switch x := v[key].(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return -1
}

func jsonStr(v map[string]interface{}, key string) string {
	if s, ok := v[key].(string); ok {
		return s
	}
	return ""
}

func jsonNum(v map[string]interface{}, keys ...string) *float64 {
	for _, k := range keys {
		switch x := v[k].(type) {
		case float64:
			if !math.IsNaN(x) && !math.IsInf(x, 0) {
				val := x
				return &val
			}
		case string:
			t := strings.ReplaceAll(x, ",", "")
			if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
				return &f
			}
		}
	}
	return nil
}

// unwrapData dépaquette récursivement les couches data/result (jusqu'à 4 niveaux)
func unwrapData(v map[string]interface{}) map[string]interface{} {
	cur := v
	for i := 0; i < 4; i++ {
		if d, ok := cur["data"].(map[string]interface{}); ok {
			cur = d
			continue
		}
		if r, ok := cur["result"].(map[string]interface{}); ok {
			cur = r
			continue
		}
		break
	}
	return cur
}

// ---- Point d'entrée principal ----

// FetchQuotaRaw récupère et normalise le quota du compte (sans écriture en base, sans changer le statut)
func (z *ZCodeAPI) FetchQuotaRaw(a *Account) (*QuotaOverview, error) {
	if a.ZCodeJWT != "" {
		ov, err := z.fetchZaiBilling(a)
		if err == nil {
			return ov, nil
		}
		// Si échec d'authentification sur le canal JWT et que le compte a une API Key, repli sur le canal monitor
		if a.APIKey != "" && (ov == nil || ov.AuthFailed || isAuthErr(err)) {
			return z.fetchApiZaiMonitor(a)
		}
		return nil, err
	}
	if a.APIKey != "" {
		return z.fetchApiZaiMonitor(a)
	}
	return nil, fmt.Errorf("Compte sans identifiants")
}

func isAuthErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "401")
}

// fetchZaiBilling canal JWT : billing/current → billing/balance
func (z *ZCodeAPI) fetchZaiBilling(a *Account) (*QuotaOverview, error) {
	urlCurrent := fmt.Sprintf("%s/billing/current?app_version=%s", BillingBaseURL, z.appVersion)
	resp, err := z.doGetJSON(a, urlCurrent, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &QuotaOverview{AuthFailed: true}, fmt.Errorf("Échec d'authentification HTTP %d", resp.StatusCode)
	}
	if resp.Body != nil {
		if code := jsonInt(resp.Body, "code"); code == 401 {
			return &QuotaOverview{AuthFailed: true}, fmt.Errorf("Code métier 401 : jeton invalide")
		}
	}
	if resp.StatusCode == 200 && businessOK(resp.Body) {
		ov := normalizeBalanceResponse(resp.Body, "zcode.z.ai/billing")
		ov.RefreshedAt = time.Now().Unix()
		return ov, nil
	}
	// Échec de current -> secours sur balance
	urlBalance := fmt.Sprintf("%s/billing/balance?app_version=%s", BillingBaseURL, z.appVersion)
	resp2, err := z.doGetJSON(a, urlBalance, nil)
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode == 401 || resp2.StatusCode == 403 {
		return &QuotaOverview{AuthFailed: true}, fmt.Errorf("Échec d'authentification HTTP %d", resp2.StatusCode)
	}
	if resp2.StatusCode == 200 && businessOK(resp2.Body) {
		ov := normalizeBalanceResponse(resp2.Body, "zcode.z.ai/billing")
		ov.RefreshedAt = time.Now().Unix()
		return ov, nil
	}
	msg := extractErrMsg(resp2.Body)
	if msg == "" {
		msg = extractErrMsg(resp.Body)
	}
	if strings.Contains(msg, "\u4e0d\u5b58\u5728coding plan") || strings.Contains(msg, "\u6ca1\u6709\u8d44\u683c") {
		return &QuotaOverview{NotEntitled: true, IsEmpty: true}, nil
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", resp2.StatusCode)
	}
	return nil, fmt.Errorf("Échec de la requête de quota : %s", msg)
}

// fetchApiZaiMonitor canal API Key : quota/limit + subscription/list
func (z *ZCodeAPI) fetchApiZaiMonitor(a *Account) (*QuotaOverview, error) {
	resp, err := z.doGetJSON(a, QuotaLimitURL, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &QuotaOverview{AuthFailed: true}, fmt.Errorf("Échec d'authentification HTTP %d", resp.StatusCode)
	}
	if !businessOK(resp.Body) {
		code := jsonInt(resp.Body, "code")
		if code == 401 {
			return &QuotaOverview{AuthFailed: true}, fmt.Errorf("Code métier 401 : jeton invalide")
		}
		msg := extractErrMsg(resp.Body)
		if strings.Contains(msg, "\u4e0d\u5b58\u5728coding plan") || strings.Contains(msg, "\u6ca1\u6709\u8d44\u683c") {
			return &QuotaOverview{NotEntitled: true, IsEmpty: true}, nil
		}
		return nil, fmt.Errorf("Échec de la requête de quota : %s", msg)
	}
	var sub *map[string]interface{}
	if subResp, err := z.doGetJSON(a, SubscriptionURL, nil); err == nil && businessOK(subResp.Body) {
		body := subResp.Body
		sub = &body
	}
	ov := normalizeQuotaLimit(resp.Body, sub)
	ov.Source = "api.z.ai/monitor"
	ov.RefreshedAt = time.Now().Unix()
	return ov, nil
}

func extractErrMsg(v map[string]interface{}) string {
	if v == nil {
		return ""
	}
	for _, k := range []string{"msg", "message", "error"} {
		if s := jsonStr(v, k); s != "" {
			return s
		}
	}
	return ""
}

// ---- Normalisation : billing/current & billing/balance (zcode.z.ai) ----

func normalizeBalanceResponse(raw map[string]interface{}, source string) *QuotaOverview {
	data := unwrapData(raw)
	ov := &QuotaOverview{Source: source}

	// plans[] : création des emplacements et déduction du tier / expire à partir du forfait actif
	slots := map[string]*QuotaPlanSlot{}
	var slotOrder []string
	var activePlan map[string]interface{}
	if plans, ok := data["plans"].([]interface{}); ok {
		for _, p := range plans {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			pid := jsonStr(pm, "plan_id")
			if pid == "" {
				continue
			}
			pname := jsonStr(pm, "name")
			status := jsonStr(pm, "status")
			if _, exists := slots[pid]; !exists {
				slots[pid] = &QuotaPlanSlot{
					PlanID: pid, Name: pname, Status: status,
					Tier:   PlanTierFromID(pid, pname),
					Expire: ExtractExpire(pm),
				}
				slotOrder = append(slotOrder, pid)
			}
			if strings.EqualFold(status, "active") && activePlan == nil {
				activePlan = pm
			}
		}
		if activePlan == nil && len(plans) > 0 {
			activePlan, _ = plans[0].(map[string]interface{})
		}
	}
	if activePlan != nil {
		pid := jsonStr(activePlan, "plan_id")
		name := jsonStr(activePlan, "name")
		ov.PlanTier = PlanTierFromID(pid, name)
		ov.PlanExpire = ExtractExpire(activePlan)
	}

	// balances[] : fragments de quota par modèle
	if balances, ok := data["balances"].([]interface{}); ok {
		var totalSum, usedSum, remSum float64
		hasTotal, hasUsed, hasRem := false, false, false
		for _, b := range balances {
			bm, ok := b.(map[string]interface{})
			if !ok {
				continue
			}
			item := QuotaItem{
				Name:      firstNonEmpty(jsonStr(bm, "show_name"), jsonStr(bm, "name"), jsonStr(bm, "entitlement_id")),
				Total:     jsonNum(bm, "total_units", "total", "limit", "usage"),
				Used:      jsonNum(bm, "used_units", "used", "consumed", "currentValue"),
				Remaining: jsonNum(bm, "remaining_units", "available_units", "remaining", "available"),
				Unit:      firstNonEmpty(jsonStr(bm, "unit_type"), jsonStr(bm, "meter")),
				PeriodEnd: ExtractExpire(bm),
			}
			if item.Name == "" {
				item.Name = "Quota"
			}
			// Déduction mutuelle des trois valeurs
			if item.Remaining == nil && item.Total != nil && item.Used != nil {
				r := math.Max(*item.Total-*item.Used, 0)
				item.Remaining = &r
			}
			if item.Total == nil && item.Used != nil && item.Remaining != nil {
				t := *item.Used + *item.Remaining
				item.Total = &t
			}
			if item.Total != nil && item.Used != nil && *item.Total > 0 {
				p := math.Min(math.Max(*item.Used / *item.Total * 100, 0), 100)
				item.PercentUsed = &p
			}
			if item.Total != nil {
				totalSum += *item.Total
				hasTotal = true
			}
			if item.Used != nil {
				usedSum += *item.Used
				hasUsed = true
			}
			if item.Remaining != nil {
				remSum += *item.Remaining
				hasRem = true
			}
			// Rangement dans le créneau correspondant
			bpid := firstNonEmpty(jsonStr(bm, "plan_id"), jsonStr(bm, "planId"))
			if bpid == "" && len(slotOrder) == 1 {
				bpid = slotOrder[0]
			}
			if bpid == "" {
				bpid = "__other__"
			}
			slot, exists := slots[bpid]
			if !exists {
				slot = &QuotaPlanSlot{PlanID: bpid, Name: "Autre quota", Tier: PlanTierFromID(bpid, "")}
				slots[bpid] = slot
				slotOrder = append(slotOrder, bpid)
			}
			slot.Items = append(slot.Items, item)
			ov.Items = append(ov.Items, item)
		}
		if hasTotal {
			ov.Total = &totalSum
		}
		if hasUsed {
			ov.Used = &usedSum
		}
		if hasRem {
			ov.Remaining = &remSum
		}
		ov.IsEmpty = len(balances) == 0
	}

	// Valeurs au premier niveau
	if ov.Total == nil {
		ov.Total = jsonNum(data, "total_units", "total")
	}
	if ov.Used == nil {
		ov.Used = jsonNum(data, "used_units", "used")
	}
	if ov.Remaining == nil {
		ov.Remaining = jsonNum(data, "available_units", "remaining_units", "remaining")
	}
	if ov.Total != nil && ov.Used != nil && *ov.Total > 0 {
		p := math.Min(math.Max(*ov.Used / *ov.Total * 100, 0), 100)
		ov.PercentUsed = &p
	}

	// Agrégation des créneaux de forfait
	for _, pid := range slotOrder {
		slot := slots[pid]
		var t, u, r float64
		hasT, hasU, hasR := false, false, false
		for _, it := range slot.Items {
			if it.Total != nil {
				t += *it.Total
				hasT = true
			}
			if it.Used != nil {
				u += *it.Used
				hasU = true
			}
			if it.Remaining != nil {
				r += *it.Remaining
				hasR = true
			}
		}
		if hasT {
			slot.Total = &t
		}
		if hasU {
			slot.Used = &u
		}
		if hasR {
			slot.Remaining = &r
		}
		if slot.Total != nil && slot.Used != nil && *slot.Total > 0 {
			p := math.Min(math.Max(*slot.Used / *slot.Total * 100, 0), 100)
			slot.PercentUsed = &p
		}
		if slot.Name == "" {
			slot.Name = pid
		}
		ov.Plans = append(ov.Plans, *slot)
	}
	if ov.PlanExpire == "" {
		ov.PlanExpire = ExtractExpire(data)
	}
	return ov
}

// ---- Normalisation : quota/limit + subscription/list (api.z.ai) ----

func normalizeQuotaLimit(raw map[string]interface{}, sub *map[string]interface{}) *QuotaOverview {
	data := unwrapData(raw)
	ov := &QuotaOverview{}

	if level := jsonStr(data, "level"); level != "" {
		ov.PlanTier = tierFromLevel(level)
	}
	limits, _ := data["limits"].([]interface{})
	for _, l := range limits {
		lm, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		typ := jsonStr(lm, "type")
		unit := jsonInt(lm, "unit")
		number := jsonInt(lm, "number")
		period := unitLabel(unit, number)
		total := jsonNum(lm, "usage", "total")
		used := jsonNum(lm, "currentValue", "used")
		remaining := jsonNum(lm, "remaining")
		name := typ
		switch typ {
		case "TOKENS_LIMIT":
			name = fmt.Sprintf("Nombre d'invites (%s)", period)
		case "TIME_LIMIT":
			name = fmt.Sprintf("Durée d'utilisation (%s)", period)
		}
		item := QuotaItem{
			Name:      name,
			Total:     total,
			Used:      used,
			Remaining: remaining,
			Unit:      typ,
		}
		if reset := jsonNum(lm, "nextResetTime"); reset != nil && *reset > 0 {
			item.PeriodEnd = formatEpochMsLocal(*reset) + " Réinitialisation"
		}
		if total != nil && used != nil && *total > 0 {
			p := math.Min(math.Max(*used / *total * 100, 0), 100)
			item.PercentUsed = &p
		} else if pct := jsonNum(lm, "percentage"); pct != nil {
			item.PercentUsed = pct
		}
		ov.Items = append(ov.Items, item)
		// Fragment principal : TIME_LIMIT en priorité (quota en minutes)
		if typ == "TIME_LIMIT" && total != nil && ov.Total == nil {
			ov.Total, ov.Used, ov.Remaining, ov.PercentUsed = total, used, remaining, item.PercentUsed
		}
	}
	if ov.Total == nil {
		for _, it := range ov.Items {
			if it.Total != nil {
				ov.Total, ov.Used, ov.Remaining, ov.PercentUsed = it.Total, it.Used, it.Remaining, it.PercentUsed
				break
			}
		}
	}
	ov.IsEmpty = len(limits) == 0

	// subscription/list complète le nom du forfait et son expiration
	if sub != nil {
		arr, _ := (*sub)["data"].([]interface{})
		var current map[string]interface{}
		for _, s := range arr {
			sm, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			valid := jsonStr(sm, "status") == "VALID"
			inPeriod := true
			if b, ok := sm["inCurrentPeriod"].(bool); ok {
				inPeriod = b
			}
			if valid && inPeriod {
				current = sm
				break
			}
		}
		if current == nil && len(arr) > 0 {
			current, _ = arr[0].(map[string]interface{})
		}
		if current != nil {
			if pn := jsonStr(current, "productName"); pn != "" {
				ov.PlanTier = tierFromLevel(pn)
			}
			ov.PlanExpire = ExtractExpire(current)
		}
	}
	return ov
}

func unitLabel(unit, number int) string {
	switch unit {
	case 3:
		if number <= 0 {
			number = 5
		}
		return fmt.Sprintf("toutes les %d heures", number)
	case 4:
		return "par jour"
	case 5:
		return "par mois"
	case 6:
		return "par semaine"
	}
	return "par cycle"
}

func tierFromLevel(level string) string {
	l := strings.ToLower(level)
	switch {
	case strings.Contains(l, "max"):
		return "Max"
	case strings.Contains(l, "pro"):
		return "Pro"
	case strings.Contains(l, "lite"):
		return "Lite"
	}
	return level
}

// PlanTierFromID déduit le niveau de forfait depuis plan_id/name
func PlanTierFromID(planID, name string) string {
	hay := strings.ToLower(planID + " " + name)
	switch {
	case strings.Contains(hay, "max"):
		return "Max"
	case strings.Contains(hay, "pro"):
		return "Pro"
	case strings.Contains(hay, "lite"):
		return "Lite"
	case strings.Contains(hay, "start"):
		return "Start Plan"
	}
	for _, kw := range []string{"trial", "taste", "experience", "gift", "weekend", "promo", "activity", "essai"} {
		if strings.Contains(hay, kw) {
			return "Essai"
		}
	}
	if planID != "" {
		return planID
	}
	return name
}

// tierRank ordre des niveaux (sélection du fragment principal lors du merge)
func tierRank(tier string) int {
	switch strings.ToLower(tier) {
	case "max":
		return 5
	case "pro":
		return 4
	case "lite":
		return 3
	case "start plan":
		return 2
	case "essai":
		return 1
	}
	return 0
}

// ExtractExpire extrait la date d'expiration d'un objet
func ExtractExpire(obj map[string]interface{}) string {
	keys := []string{"nextRenewTime", "expireTime", "expire_time", "endTime", "end_time",
		"expireAt", "expiredTime", "validEndTime", "expires_at", "expiresAt", "expired_at",
		"period_end", "nextResetTime", "ends_at"}
	for _, k := range keys {
		v, ok := obj[k]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case float64:
			if x > 1e12 {
				return formatEpochMsLocal(x)
			}
			if x > 1e9 {
				return time.Unix(int64(x), 0).Format("2006-01-02 15:04")
			}
		case string:
			t := strings.TrimSpace(x)
			if t == "" {
				continue
			}
			if n, err := strconv.ParseFloat(t, 64); err == nil {
				if n > 1e12 {
					return formatEpochMsLocal(n)
				}
				if n > 1e9 {
					return time.Unix(int64(n), 0).Format("2006-01-02 15:04")
				}
			}
			if ts, err := time.Parse(time.RFC3339, t); err == nil {
				return ts.Local().Format("2006-01-02 15:04")
			}
			t = strings.Replace(t, "T", " ", 1)
			if len(t) >= 16 && t[4] == '-' && t[7] == '-' {
				return t[:16]
			}
			if len(t) == 10 && t[4] == '-' && t[7] == '-' {
				return t
			}
			return t
		}
	}
	return ""
}

func formatEpochMsLocal(ms float64) string {
	return time.UnixMilli(int64(ms)).Format("2006-01-02 15:04")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---- Détermination du statut ----

// AllExhausted tous les fragments ont un quota restant <= 0
func (ov *QuotaOverview) AllExhausted() bool {
	if len(ov.Items) == 0 {
		return ov.Remaining != nil && *ov.Remaining <= 0
	}
	for _, it := range ov.Items {
		if it.Remaining == nil || *it.Remaining > 0 {
			return false
		}
	}
	return true
}

// SortItemsByRemaining trie avec les plus grands quotas restants en premier (affichage best_quota)
func SortItemsByRemaining(items []QuotaItem) {
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := 0.0, 0.0
		if items[i].Remaining != nil {
			ri = *items[i].Remaining
		}
		if items[j].Remaining != nil {
			rj = *items[j].Remaining
		}
		return ri > rj
	})
}

// Référence défensive pour strconv
var _ = strconv.Itoa
