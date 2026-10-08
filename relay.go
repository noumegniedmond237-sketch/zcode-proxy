package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ---- Cœur de relais 2API ----
// Portage de gateway.py de zcode2api : rotation multi-comptes + bascule automatique en cas de quota épuisé + chaîne de repli captcha.
// Chaîne de repli : JWT + captcha → JWT direct sans paramètre → repli API Key (api.z.ai).

const (
	maxCaptchaRetries  = 3
	maxAccountAttempts = 5
	maxRequestBytes    = 8 << 20
)

// modelNameMap normalisation insensible à la casse des noms de modèles amont
var modelNameMap = map[string]string{
	"glm-5.3":       "GLM-5.3",
	"glm-5.2":       "GLM-5.2",
	"glm-5-turbo":   "GLM-5-Turbo",
	"glm-turbo":     "GLM-5-Turbo",
	"glm-5.1":       "GLM-5.1",
	"glm-4.7":       "GLM-4.7",
	"glm-4.6":       "GLM-4.6",
	"glm-4.5":       "GLM-4.5",
	"glm-4.5-air":   "GLM-4.5-Air",
	"glm-4.5v":      "GLM-4.5V",
	"glm-4.5-flash": "GLM-4.5-Flash",
}

// relayOutcome résultat d'un relais
type relayOutcome int

const (
	outcomeWritten       relayOutcome = iota // Réponse écrite au client
	outcomeNextAccount                       // Compte indisponible, passer au suivant
	outcomeCaptchaRejected                   // Captcha rejeté, tenter le chemin suivant
	outcomeUpstreamError                     // Erreur finale amont (déjà écrite)
	outcomeRiskBlocked                       // Bloqué par contrôle de sécurité (3012), tenter le chemin suivant
)

// protocol type de protocole client (détermine la conversion)
type protocol int

const (
	protocolAnthropic protocol = iota
	protocolOpenAI
	protocolResponses
)

// relayCtx contexte d'une requête de relais
type relayCtx struct {
	body         map[string]interface{} // Corps au format Anthropic normalisé
	provider     string
	group        string
	proto        protocol
	clientStream bool   // Si le client attend du SSE
	clientModel  string // Nom du modèle renvoyé au client
	includeUsage bool   // OpenAI stream_options.include_usage
}

// HandleMessages POST /v1/messages — Protocole natif Anthropic
func (z *ZCodeAPI) HandleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, errResp := readJSONBody(r)
	if errResp != nil {
		errResp.Write(w)
		return
	}
	provider := detectProvider(body, r.Header)
	if err := normalizeBody(body, z); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateMessagesBody(body); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	clientStream, _ := body["stream"].(bool)
	model, _ := body["model"].(string)
	rc := &relayCtx{
		body: body, provider: provider, group: r.Header.Get("x-zcode-group"),
		proto: protocolAnthropic, clientStream: clientStream, clientModel: model,
	}
	z.relay(w, r, rc)
}

// relay sélectionne un compte et relaie via la chaîne de repli
func (z *ZCodeAPI) relay(w http.ResponseWriter, r *http.Request, rc *relayCtx) {
	payload, _ := json.Marshal(rc.body)
	tried := map[int64]bool{}
	var reasons []string
	start := time.Now()

	for attempt := 0; attempt < maxAccountAttempts; attempt++ {
		a := z.pool.Select(rc.provider, rc.group, tried)
		if a == nil {
			break
		}
		tried[a.ID] = true

		outcome := z.tryAccount(w, r, a, payload, rc, &reasons, start)
		switch outcome {
		case outcomeWritten, outcomeUpstreamError:
			return
		case outcomeNextAccount, outcomeCaptchaRejected:
			continue
		}
	}

	detail := strings.Join(dedup(reasons), " ; ")
	if len(detail) > 400 {
		detail = detail[:400] + "…"
	}
	msg := "Tous les comptes sont indisponibles ou ont épuisé leur quota, vérifiez l'état des comptes dans l'administration"
	// Si aucun compte disponible en raison du refroidissement, indiquer le délai estimé
	if until, reason := z.pool.CoolingInfo(rc.provider, rc.group); until > 0 {
		secs := until - time.Now().Unix()
		if secs < 0 {
			secs = 0
		}
		msg = fmt.Sprintf("Comptes en refroidissement (%s), reprise automatique dans environ %d secondes", firstNonEmpty(reason, "limitation amont / contrôle"), secs)
	}
	if detail != "" {
		msg += " (dernières causes d'échec : " + detail + ")"
	}
	log.Printf("[relay] no available account: %s", detail)
	writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
		"error": map[string]string{"message": msg, "type": "no_available_account"},
	})
}

// tryAccount chaîne de repli pour un compte : JWT+captcha → JWT direct → repli API Key.
// Le canal gratuit exige une validation captcha (paramètre réutilisable 45s).
// Le blocage de contrôle (3012) ne refroidit pas immédiatement : teste les autres chemins du compte d'abord.
func (z *ZCodeAPI) tryAccount(w http.ResponseWriter, r *http.Request, a *Account,
	payload []byte, rc *relayCtx, reasons *[]string, start time.Time) relayOutcome {

	note := func(msg string) {
		*reasons = append(*reasons, a.DisplayNameOrEmail()+": "+msg)
	}
	riskBlocked := false

	needsCaptcha := rc.provider == "zai" && a.AuthType == "jwt" && a.ZCodeJWT != ""

	// Chemin 1 : JWT + captcha Alibaba Cloud sans trace
	if needsCaptcha {
		verifyParam, region, err := z.captcha.GetVerifyParam(a)
		if err != nil {
			verifyParam = ""
			note("Échec de résolution du captcha : " + truncate(err.Error(), 180))
		}
		out := z.forwardOnce(w, r, a, payload, verifyParam, region, false, maxCaptchaRetries, rc, start, "jwt-captcha")
		switch out {
		case outcomeWritten, outcomeUpstreamError:
			return out
		case outcomeNextAccount:
			note("Compte indisponible : " + firstNonEmpty(a.LastError, a.Status))
			return outcomeNextAccount
		case outcomeRiskBlocked:
			riskBlocked = true
			note("Contrôle de sécurité amont sur le canal gratuit (unusual activity)")
		case outcomeCaptchaRejected:
			note("Requête avec captcha rejetée par l'amont")
		}
	}

	// Chemin 2 : JWT direct sans paramètre de validation
	if a.ZCodeJWT != "" && !riskBlocked {
		out := z.forwardOnce(w, r, a, payload, "", "", false, 2, rc, start, "jwt-direct")
		switch out {
		case outcomeWritten, outcomeUpstreamError:
			return out
		case outcomeNextAccount:
			note("Compte indisponible : " + firstNonEmpty(a.LastError, a.Status))
			return outcomeNextAccount
		case outcomeRiskBlocked:
			riskBlocked = true
			note("Contrôle de sécurité amont sur le canal gratuit (unusual activity)")
		case outcomeCaptchaRejected:
			note("Connexion directe rejetée : captcha exigé")
		}
	}

	// Chemin 3 : Point d'accès de repli API Key (api.z.ai, sans captcha)
	if a.APIKey != "" {
		out := z.forwardOnce(w, r, a, payload, "", "", true, 2, rc, start, "apikey")
		switch out {
		case outcomeWritten, outcomeUpstreamError:
			return out
		case outcomeNextAccount:
			note("Échec du repli API Key : " + firstNonEmpty(a.LastError, a.Status))
			return outcomeNextAccount
		case outcomeRiskBlocked:
			note("Canal API Key également bloqué par contrôle de sécurité")
		case outcomeCaptchaRejected:
			note("Repli API Key refusé (captcha requis)")
		}
	} else if !needsCaptcha {
		note("Aucune clé API de repli disponible")
	}

	// Tous les chemins ont échoué : refroidissement si contrôle de sécurité
	if riskBlocked {
		z.pool.MarkCooling(a, "Contrôle amont (unusual activity), tous les canaux ont échoué", 120)
	}
	log.Printf("[relay] account %s all paths failed", a.Email)
	return outcomeNextAccount
}

// forwardOnce relais sur un chemin unique ; pathLabel pour les logs
func (z *ZCodeAPI) forwardOnce(w http.ResponseWriter, r *http.Request, a *Account,
	payload []byte, verifyParam, region string, useFallback bool, retries int,
	rc *relayCtx, start time.Time, pathLabel string) relayOutcome {

	// Requête amont en streaming systématique pour OpenAI/Responses afin de faciliter l'agrégation
	upstreamStream := rc.clientStream || rc.proto != protocolAnthropic

	for attempt := 0; attempt < retries; attempt++ {
		urlStr, headers := z.buildUpstreamRequest(a, verifyParam, region, useFallback, r, upstreamStream)
		req, err := http.NewRequestWithContext(r.Context(), "POST", urlStr, bytes.NewReader(payload))
		if err != nil {
			// Erreur de construction locale (problème de configuration)
			log.Printf("[relay] build request failed: %v", err)
			writeAPIError(w, http.StatusInternalServerError, "Échec de construction de la requête amont")
			return outcomeUpstreamError
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		client := ClientForURL(z.egress.ProxyURLForAccount(a), urlStr, 0) // Pas de timeout global en streaming, contrôlé par context
		resp, err := client.Do(req)
		if err != nil {
			// Déconnexion / annulation client
			if r.Context().Err() != nil || errors.Is(err, context.Canceled) {
				return outcomeUpstreamError
			}
			z.pool.MarkCooling(a, "Échec de connexion : "+truncate(err.Error(), 180), 60)
			return outcomeNextAccount
		}

		// 3xx : Défi WAF / redirection de page de connexion
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp.Body.Close()
			z.pool.MarkCooling(a, fmt.Sprintf("Redirection amont HTTP %d (défi WAF suspecté)", resp.StatusCode), 120)
			return outcomeNextAccount
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			text := string(body)

			// Captcha rejeté : invalider le cache -> résoudre à nouveau -> réessayer ce chemin
			if isCaptchaError(text) && (resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403) {
				if verifyParam != "" && attempt+1 < retries {
					z.captcha.InvalidateFor(a)
					log.Printf("[relay] account %s captcha rejected, re-solving", a.Email)
					newParam, newRegion, err := z.captcha.GetVerifyParam(a)
					if err == nil && newParam != "" {
						verifyParam, region = newParam, newRegion
						continue
					}
				}
				return outcomeCaptchaRejected
			}

			switch {
			case resp.StatusCode == 401 || resp.StatusCode == 403:
				z.pool.MarkInvalid(a, fmt.Sprintf("Échec d'authentification HTTP %d", resp.StatusCode))
				return outcomeNextAccount
			case resp.StatusCode == 429:
				// Limitation souvent due à un pic RPM temporaire : recul dans la requête puis bref refroidissement
				retryAfter := 2
				if ra := resp.Header.Get("Retry-After"); ra != "" {
					if n, err := strconv.Atoi(ra); err == nil && n > 0 && n <= 5 {
						retryAfter = n
					}
				}
				if attempt+1 < retries {
					log.Printf("[relay] account %s model %s rate-limited 429, retrying in %ds", a.DisplayNameOrEmail(), rcModel(payload), retryAfter)
					resp.Body.Close()
					time.Sleep(time.Duration(retryAfter) * time.Second)
					continue
				}
				z.pool.MarkCooling(a, fmt.Sprintf("Limitation amont 429 (model=%s)", rcModel(payload)), 30)
				return outcomeNextAccount
			case isRiskBlocked(text):
				// 3012 unusual activity : blocage contrôle de sécurité sur canal gratuit
				log.Printf("[relay] account %s risk-blocked on %s path", a.DisplayNameOrEmail(), pathLabel)
				return outcomeRiskBlocked
			case isExhaustedError(resp.StatusCode, text):
				z.pool.MarkExhausted(a, "Quota épuisé")
				go z.RefreshAccountQuota(a)
				return outcomeNextAccount
			}

			// Autres erreurs amont : retransmettre au client selon le protocole
			z.pool.MarkFailed(a, fmt.Sprintf("Erreur amont HTTP %d", resp.StatusCode))
			z.recordUsage(a, r, payload, resp.StatusCode, start, 0, nil, rc.clientStream)
			writeUpstreamErrorForProto(w, resp, text, rc.proto)
			return outcomeUpstreamError
		}

		// ---- Succès ----
		z.pool.MarkUsed(a)
		go z.RefreshAccountQuotaThrottled(a)
		log.Printf("[relay] account %s success via %s (HTTP %d)", a.DisplayNameOrEmail(), pathLabel, resp.StatusCode)

		contentType := resp.Header.Get("Content-Type")
		isStream := strings.Contains(contentType, "text/event-stream")
		// 2xx mais non JSON/SSE (HTML de défi WAF / login) : traité comme erreur amont
		if !isStream && !strings.Contains(contentType, "json") {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			z.pool.MarkCooling(a, fmt.Sprintf("L'amont a renvoyé du contenu non JSON (%s)", truncate(contentType, 60)), 120)
			writeUpstreamErrorForProto(w, resp, string(body), rc.proto)
			return outcomeUpstreamError
		}

		if !isStream {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			resp.Body.Close()
			usage := parseAnthropicUsageJSON(body)
			z.recordUsage(a, r, payload, resp.StatusCode, start, 0, usage, rc.clientStream)
			writeProtocolResponse(w, rc.proto, resp.StatusCode, contentType, body, usage, rc.clientModel)
			return outcomeWritten
		}

		streamProtocolResponse(w, rc, resp, a, r, payload, z, start)
		return outcomeWritten
	}
	return outcomeCaptchaRejected // Nombre maximal de tentatives atteint
}

// buildUpstreamRequest assemble l'URL et les en-têtes amont
func (z *ZCodeAPI) buildUpstreamRequest(a *Account, verifyParam, region string, useFallback bool, r *http.Request, stream bool) (string, map[string]string) {
	up := z.cfg.GetUpstream()
	var urlStr string
	headers := map[string]string{}

	if useFallback && a.APIKey != "" {
		// Le point d'accès de repli dépend du provider : la clé bigmodel ne peut être envoyée que sur le canal bigmodel
		if a.Provider == "bigmodel" {
			urlStr = up.Bigmodel
		} else {
			urlStr = up.ZaiFallback
		}
		headers["x-api-key"] = a.APIKey
	} else if a.ZCodeJWT != "" && !useFallback {
		if a.Provider == "bigmodel" {
			urlStr = up.Bigmodel
		} else {
			urlStr = up.Zai
		}
		headers["Authorization"] = "Bearer " + a.ZCodeJWT
	} else if a.APIKey != "" {
		urlStr = up.ZaiFallback
		headers["x-api-key"] = a.APIKey
	} else {
		urlStr = up.Zai
	}

	// En-têtes d'identité client (conformes au client desktop)
	id := NewClientIdentity(z.appVersion, a.DeviceMid)
	for k, v := range ZaiClientHeaders(id) {
		headers[k] = v
	}
	headers["content-type"] = "application/json"
	if stream {
		headers["accept"] = "text/event-stream"
	} else {
		headers["accept"] = "application/json"
	}
	headers["anthropic-version"] = anthropicVersionH
	headers["X-ZCode-Agent"] = "glm"
	if verifyParam != "" {
		headers["X-Aliyun-Captcha-Verify-Param"] = verifyParam
		if region != "" {
			headers["X-Aliyun-Captcha-Verify-Region"] = region
		}
	}

	// En-têtes clients transférés en liste blanche
	forwardSet := map[string]bool{
		"accept-language": true, "cache-control": true, "anthropic-beta": true,
		"anthropic-dangerous-direct-browser-access": true, "traceparent": true,
		"tracestate": true, "x-client-request-id": true,
	}
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if forwardSet[lk] || strings.HasPrefix(lk, "x-stainless-") {
			if len(vals) > 0 && len(vals[0]) <= 4096 {
				headers[lk] = vals[0]
			}
		}
	}
	return urlStr, headers
}

// DisplayNameOrEmail nom d'affichage du compte
func (a *Account) DisplayNameOrEmail() string {
	return firstNonEmpty(a.DisplayName, a.Email, a.UserID)
}

// ---- Détection des erreurs (portage de gateway.py) ----

// rcModel extrait le modèle depuis le corps de requête (pour les logs)
func rcModel(payload []byte) string {
	var b struct {
		Model string `json:"model"`
	}
	json.Unmarshal(payload, &b)
	return b.Model
}

func isCaptchaError(text string) bool {
	low := strings.ToLower(text)
	for _, m := range []string{"captcha", "verify token", "verify failed", "human verification", "verifycode"} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func isExhaustedError(statusCode int, text string) bool {
	if statusCode == 402 {
		return true
	}
	low := strings.ToLower(text)
	for _, m := range []string{
		"insufficient balance", "insufficient funds", "no resource package",
		"resource package exhausted", "quota exceeded", "\u4f59\u989d\u4e0d\u8db3", "\u989d\u5ea6\u5df2\u7528\u5b8c",
	} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// isRiskBlocked détection de blocage par contrôle de sécurité (code 3012 / unusual activity)
func isRiskBlocked(text string) bool {
	low := strings.ToLower(text)
	return strings.Contains(low, "unusual activity") || strings.Contains(low, `"code":3012`)
}

// ---- Traitement du corps de requête ----

func readJSONBody(r *http.Request) (map[string]interface{}, *errorResponse) {
	if r.ContentLength > maxRequestBytes {
		return nil, &errorResponse{status: http.StatusRequestEntityTooLarge, msg: "Corps de requête trop volumineux"}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		return nil, &errorResponse{status: http.StatusBadRequest, msg: "Échec de lecture du corps de requête"}
	}
	if len(data) > maxRequestBytes {
		return nil, &errorResponse{status: http.StatusRequestEntityTooLarge, msg: "Corps de requête trop volumineux"}
	}
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, &errorResponse{status: http.StatusBadRequest, msg: "Le corps de requête n'est pas un JSON valide"}
	}
	return v, nil
}

type errorResponse struct {
	status int
	msg    string
}

func (e *errorResponse) Write(w http.ResponseWriter) {
	writeAPIError(w, e.status, e.msg)
}

func detectProvider(body map[string]interface{}, h http.Header) string {
	model, _ := body["model"].(string)
	if strings.HasPrefix(model, "bigmodel/") || h.Get("x-provider") == "bigmodel" {
		return "bigmodel"
	}
	return "zai"
}

// normalizeBody normalisation du nom de modèle + max_tokens par défaut + réflexion forcée GLM-5.3 + pontage de content
func normalizeBody(body map[string]interface{}, z *ZCodeAPI) error {
	model, _ := body["model"].(string)
	if strings.Contains(model, "/") {
		parts := strings.SplitN(model, "/", 2)
		model = parts[1]
	}
	model = strings.TrimSpace(model)
	if official, ok := modelNameMap[strings.ToLower(model)]; ok {
		model = official
	} else {
		for _, m := range z.cfg.GetModels() {
			if strings.EqualFold(m, model) {
				model = m
				break
			}
		}
	}
	body["model"] = model

	if _, ok := body["max_tokens"]; !ok {
		body["max_tokens"] = float64(4096)
	}
	fixThinking(body)

	// string content → [{type:text,text:...}]
	if msgs, ok := body["messages"].([]interface{}); ok {
		for i, m := range msgs {
			mm, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := mm["content"].(string); ok {
				nm := map[string]interface{}{
					"content": []interface{}{map[string]interface{}{"type": "text", "text": s}},
				}
				for k, v := range mm {
					if k != "content" {
						nm[k] = v
					}
				}
				msgs[i] = nm
			}
		}
		body["messages"] = msgs
	}
	return nil
}

// fixThinking mode de réflexion forcée pour GLM-5.3 (l'amont n'autorise pas sa désactivation)
func fixThinking(body map[string]interface{}) {
	model, _ := body["model"].(string)
	if !strings.Contains(model, "5.3") {
		return
	}
	maxTokens := 4096
	if mt, ok := body["max_tokens"].(float64); ok {
		maxTokens = int(mt)
	}
	if maxTokens < 1024 {
		maxTokens = 1024
	}
	budget := 8192
	if budget > maxTokens-1024 {
		budget = maxTokens - 1024
	}
	if budget < 1024 {
		budget = 1024
	}
	thinking, _ := body["thinking"].(map[string]interface{})
	if thinking == nil || thinking["type"] != "enabled" {
		thinking = map[string]interface{}{"type": "enabled", "budget_tokens": budget}
	} else if _, ok := thinking["budget_tokens"]; !ok {
		thinking["budget_tokens"] = budget
	}
	body["thinking"] = thinking
	if _, ok := body["reasoning_effort"]; !ok {
		body["reasoning_effort"] = "max"
	}
}

func validateMessagesBody(body map[string]interface{}) error {
	model, ok := body["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return fmt.Errorf("model must be a non-empty string")
	}
	if len(model) > 200 {
		return fmt.Errorf("model is too long")
	}
	msgs, ok := body["messages"].([]interface{})
	if !ok || len(msgs) == 0 {
		return fmt.Errorf("messages must contain at least one message")
	}
	if len(msgs) > 1000 {
		return fmt.Errorf("messages contains too many items")
	}
	for i, m := range msgs {
		mm, ok := m.(map[string]interface{})
		if !ok {
			return fmt.Errorf("messages[%d] must be an object", i)
		}
		role, _ := mm["role"].(string)
		if role != "user" && role != "assistant" {
			return fmt.Errorf("messages[%d].role must be user or assistant", i)
		}
		switch c := mm["content"].(type) {
		case string:
			if len(c) > 2_000_000 {
				return fmt.Errorf("messages[%d].content is too long", i)
			}
		case nil:
			return fmt.Errorf("messages[%d].content must be string or array", i)
		default:
			// Repli par réflexion : les convertisseurs peuvent produire []map[string]interface{}
			rv := reflect.ValueOf(c)
			if rv.Kind() != reflect.Slice {
				return fmt.Errorf("messages[%d].content must be string or array", i)
			}
			if rv.Len() > 2_000_000 {
				return fmt.Errorf("messages[%d].content is too long", i)
			}
			for j := 0; j < rv.Len(); j++ {
				bm, ok := rv.Index(j).Interface().(map[string]interface{})
				if !ok {
					return fmt.Errorf("messages[%d].content[%d] must be an object", i, j)
				}
				if _, ok := bm["type"].(string); !ok {
					return fmt.Errorf("messages[%d].content[%d] must have a type", i, j)
				}
			}
		}
	}
	if mt, ok := body["max_tokens"]; ok {
		switch v := mt.(type) {
		case float64:
			if v < 1 || v > 1_000_000 {
				return fmt.Errorf("max_tokens must be between 1 and 1000000")
			}
		default:
			return fmt.Errorf("max_tokens must be a number")
		}
	}
	if s, ok := body["stream"]; ok {
		if _, isBool := s.(bool); !isBool {
			return fmt.Errorf("stream must be a boolean")
		}
	}
	return nil
}

// dedup déduplique en conservant l'ordre
func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// writeUpstreamErrorForProto retransmet l'erreur amont selon le protocole client
func writeUpstreamErrorForProto(w http.ResponseWriter, resp *http.Response, text string, proto protocol) {
	if proto != protocolAnthropic {
		// Erreur style OpenAI
		msg := "upstream error"
		var payload map[string]interface{}
		if json.Unmarshal([]byte(text), &payload) == nil {
			if e, ok := payload["error"].(map[string]interface{}); ok {
				if m, ok := e["message"].(string); ok && m != "" {
					msg = m
				}
			}
		}
		writeJSON(w, resp.StatusCode, map[string]interface{}{
			"error": map[string]interface{}{"message": truncate(msg, 500), "type": "api_error", "code": resp.StatusCode},
		})
		return
	}
	for _, k := range []string{"retry-after", "x-request-id", "request-id"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	var v map[string]interface{}
	if json.Unmarshal([]byte(text), &v) == nil {
		w.Write([]byte(text))
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"message": truncate(text, 500), "type": "upstream_error"},
	})
}

// RefreshAccountQuotaThrottled actualisation immédiate du quota après succès (régulation 30s)
func (z *ZCodeAPI) RefreshAccountQuotaThrottled(a *Account) {
	if a.Provider != "zai" || a.ZCodeJWT == "" {
		return
	}
	if time.Now().Unix()-a.LastCheckedAt < 30 {
		return
	}
	if err := z.RefreshAccountQuota(a); err != nil {
		log.Printf("[quota] throttled refresh %s: %v", a.Email, err)
	}
}

// recordUsage enregistre dans usage_records ; clientStream représente le mode réel de la requête client
func (z *ZCodeAPI) recordUsage(a *Account, r *http.Request, payload []byte, statusCode int, start time.Time, ttftMs int, usage *StreamUsage, clientStream bool) {
	var body map[string]interface{}
	json.Unmarshal(payload, &body)
	model, _ := body["model"].(string)
	rec := &UsageRecord{
		AccountID:  a.ID,
		Email:      firstNonEmpty(a.Email, a.DisplayName),
		Model:      model,
		Stream:     clientStream,
		StatusCode: statusCode,
		DurationMs: int(time.Since(start).Milliseconds()),
		TtftMs:     ttftMs,
	}
	if usage != nil {
		rec.PromptTokens = usage.InputTokens
		rec.CompletionTokens = usage.OutputTokens
		rec.TotalTokens = usage.InputTokens + usage.OutputTokens
	}
	if err := z.db.InsertUsageRecord(rec); err != nil {
		log.Printf("[usage] insert: %v", err)
	}
}
