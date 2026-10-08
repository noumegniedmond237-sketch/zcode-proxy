package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

// ---- Service de résolution du captcha invisible Aliyun ----
// Portage de zcode2api captcha.py (Playwright → go-rod) :
//   1. GET client/configs récupère la configuration captcha (prefix/region/sceneId, cache 10 minutes)
//   2. un vrai Chrome/Edge local (le Chromium embarqué est détecté par l'anti-fraude) ouvre une page de même origine zcode.z.ai
//   3. injecte le HTML du SDK de vérification invisible Aliyun, déclenche automatiquement startTracelessVerification
//   4. le callback window.__onCaptcha capture le param success (soit X-Aliyun-Captcha-Verify-Param)
//   5. le paramètre est mis en cache 45 s par groupe de proxy de sortie ; après expiration, l'ancienne valeur est renvoyée pendant 300 s de grâce avec rafraîchissement en arrière-plan
//   6. en cas d'échec headless, bascule automatique en fenêtre visible pour validation manuelle, le résultat est également mis en cache
// Modèle de concurrence : un sémaphore de capacité 1 garantit une seule résolution à la fois (TryAcquire non bloquant pour le rafraîchissement en arrière-plan),
// aucun chemin de fuite de verrou.

const (
	captchaCacheTTL     = 45 * time.Second
	captchaStaleGrace   = 300 * time.Second
	captchaFailCacheTTL = 60 * time.Second
	captchaConfigTTL    = 10 * time.Minute
	captchaSolveTimeout = 40 * time.Second
	captchaSolveRetries = 4
	captchaChromeUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

// CaptchaConfig configuration du captcha (réponse client/configs)
type CaptchaConfig struct {
	Enabled bool   `json:"enabled"`
	Region  string `json:"region"`
	Prefix  string `json:"prefix"`
	SceneID string `json:"scene_id"`
}

type captchaCacheEntry struct {
	param  string
	region string
	at     time.Time
}

// CaptchaService service de résolution du captcha (sûr en concurrence)
type CaptchaService struct {
	cfg        *FileConfig
	db         *DB
	appVersion string

	mu       sync.Mutex
	cache    map[string]*captchaCacheEntry // key = URL du proxy de sortie (isolation par groupe de proxys)
	failAt   map[string]time.Time
	config   *CaptchaConfig
	configAt time.Time
	solveSem chan struct{} // sémaphore de capacité 1 : résolution unique globale
	manual   bool          // mode manuel avec interface (bascule après échec automatique)
}

// NewCaptchaService crée le service captcha
func NewCaptchaService(cfg *FileConfig, db *DB, appVersion string) *CaptchaService {
	return &CaptchaService{
		cfg:        cfg,
		db:         db,
		appVersion: appVersion,
		cache:      make(map[string]*captchaCacheEntry),
		failAt:     make(map[string]time.Time),
		solveSem:   make(chan struct{}, 1),
	}
}

func (s *CaptchaService) cacheKey(a *Account) string {
	return captchaProxyHook(a)
}

// captchaHTML page d'injection de la vérification invisible Aliyun (identique mot pour mot à zcode2api ; valeurs de configuration échappées en JSON contre l'injection)
func captchaHTML(sceneID, region, prefix string) string {
	js := func(v string) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"></script>
</head><body><div id="cap"></div><button id="btn"></button>
<script>
window.initAliyunCaptcha({
  SceneId: ` + js(sceneID) + `, mode: 'popup', region: ` + js(region) + `, prefix: ` + js(prefix) + `,
  element: '#cap', button: '#btn', captchaLogoImg: '', showErrorTip: false,
  getInstance: function (inst) {
    var fn = inst.startTracelessVerification || inst.show;
    try { fn.call(inst); } catch (e) {
      window.__onCaptcha(JSON.stringify({event: 'starterr', message: String(e && e.message || e)}));
    }
  },
  success: function (param) { window.__onCaptcha(JSON.stringify({event: 'success', param: param})); },
  fail: function (m) { window.__onCaptcha(JSON.stringify({event: 'fail', reason: m})); },
  onError: function (m) { window.__onCaptcha(JSON.stringify({event: 'error', reason: m})); }
});
</script></body></html>`
}

// GetVerifyParam obtient un paramètre de vérification valide (cache → ancienne valeur de grâce → nouvelle résolution)
func (s *CaptchaService) GetVerifyParam(a *Account) (param, region string, err error) {
	mode := s.getSetting("captcha_mode")
	if mode == "off" {
		return "", "", nil // Captcha désactivé : connexion directe (l'amont a pu s'assouplir)
	}
	key := s.cacheKey(a)

	s.mu.Lock()
	if e, ok := s.cache[key]; ok {
		age := time.Since(e.at)
		if age < captchaCacheTTL {
			p, r := e.param, e.region
			s.mu.Unlock()
			return p, r, nil
		}
		if age < captchaCacheTTL+captchaStaleGrace {
			p, r := e.param, e.region
			s.mu.Unlock()
			go s.refreshInBackground(a) // Période de grâce : ancienne valeur d'abord, rafraîchissement en arrière-plan
			return p, r, nil
		}
	}
	if t, ok := s.failAt[key]; ok && time.Since(t) < captchaFailCacheTTL {
		s.mu.Unlock()
		return "", "", fmt.Errorf("Échec récent de résolution du captcha (refroidissement anti-fraude), veuillez réessayer plus tard")
	}
	s.mu.Unlock()

	return s.solveOnce(a)
}

func (s *CaptchaService) getSetting(key string) string {
	if s.db == nil {
		return ""
	}
	v, _ := s.db.GetSetting(key)
	return v
}

// tryAcquireSolve acquiert le droit de résolution sans bloquer (pour le rafraîchissement en arrière-plan ; un échec signifie qu'une résolution est déjà en cours)
func (s *CaptchaService) tryAcquireSolve() bool {
	select {
	case s.solveSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *CaptchaService) releaseSolve() { <-s.solveSem }

func (s *CaptchaService) refreshInBackground(a *Account) {
	if !s.tryAcquireSolve() {
		return
	}
	defer s.releaseSolve()
	s.doSolve(a)
}

func (s *CaptchaService) solveOnce(a *Account) (string, string, error) {
	s.solveSem <- struct{}{} // Acquisition bloquante (chemin synchrone, sans fuite : defer libère toujours)
	defer s.releaseSolve()

	key := s.cacheKey(a)
	// Double vérification : une autre requête a pu réussir la résolution pendant l'attente du sémaphore
	s.mu.Lock()
	if e, ok := s.cache[key]; ok && time.Since(e.at) < captchaCacheTTL {
		p, r := e.param, e.region
		s.mu.Unlock()
		return p, r, nil
	}
	s.mu.Unlock()
	return s.doSolve(a)
}

func (s *CaptchaService) doSolve(a *Account) (string, string, error) {
	key := s.cacheKey(a)
	cc, err := s.fetchConfig(a)
	if err != nil {
		s.markFail(key)
		return "", "", err
	}
	if !cc.Enabled {
		return "", "", nil // Captcha non activé en amont
	}

	mode := s.getSetting("captcha_mode")
	headless := mode != "manual" && !s.manual

	var lastErr error
	for attempt := 1; attempt <= captchaSolveRetries; attempt++ {
		param, err := s.solveWithBrowser(cc, headless, a)
		if err == nil && param != "" {
			s.mu.Lock()
			s.cache[key] = &captchaCacheEntry{param: param, region: cc.Region, at: time.Now()}
			delete(s.failAt, key)
			s.manual = false // Retour au mode headless après succès
			s.mu.Unlock()
			log.Printf("[captcha] solved (headless=%v, attempt=%d, len=%d)", headless, attempt, len(param))
			return param, cc.Region, nil
		}
		lastErr = err
		log.Printf("[captcha] solve attempt %d failed (headless=%v): %v", attempt, headless, err)
		// Après 2 échecs headless consécutifs, bascule en mode manuel avec interface
		if headless && attempt >= 2 {
			headless = false
			s.mu.Lock()
			s.manual = true
			s.mu.Unlock()
			log.Printf("[captcha] switching to headed manual mode")
		}
	}
	s.markFail(key)
	return "", "", fmt.Errorf("Échec de la résolution du captcha (%d tentatives) : %v", captchaSolveRetries, lastErr)
}

func (s *CaptchaService) markFail(key string) {
	s.mu.Lock()
	s.failAt[key] = time.Now()
	s.mu.Unlock()
}

// InvalidateFor invalide le cache de ce proxy de sortie en cas de rejet amont
func (s *CaptchaService) InvalidateFor(a *Account) {
	s.mu.Lock()
	delete(s.cache, s.cacheKey(a))
	s.mu.Unlock()
}

// Invalidate invalide tout le cache
func (s *CaptchaService) Invalidate() {
	s.mu.Lock()
	s.cache = make(map[string]*captchaCacheEntry)
	s.mu.Unlock()
}

// Status état du service (affichage UI)
func (s *CaptchaService) Status() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	has, fresh, oldest := false, false, time.Duration(0)
	for _, e := range s.cache {
		has = true
		age := time.Since(e.at)
		if age < captchaCacheTTL {
			fresh = true
		}
		if age > oldest {
			oldest = age
		}
	}
	return map[string]interface{}{
		"has_param":   has,
		"param_age_s": int(oldest.Seconds()),
		"fresh":       fresh,
		"manual_mode": s.manual,
		"cache_keys":  len(s.cache),
		"config":      s.config,
	}
}

// fetchConfig récupère et met en cache la configuration captcha
func (s *CaptchaService) fetchConfig(a *Account) (*CaptchaConfig, error) {
	s.mu.Lock()
	if s.config != nil && time.Since(s.configAt) < captchaConfigTTL {
		c := s.config
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	urlStr := fmt.Sprintf("%s?version=%s&os=%s", ClientConfigsURL, s.appVersion, NodePlatform())
	// L'interface de configuration ne requiert pas d'authentification, requête brute directe (zcode.z.ai → client empreinte)
	client := ClientForURL("", urlStr, 20*time.Second)
	req, _ := http.NewRequest("GET", urlStr, nil)
	id := NewClientIdentity(s.appVersion, "")
	for k, v := range ZaiClientHeaders(id) {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Échec de récupération de la configuration captcha : %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Configs struct {
				Captcha struct {
					Enabled bool   `json:"enabled"`
					Prefix  string `json:"prefix"`
					Region  string `json:"region"`
					SceneID string `json:"sceneId"`
				} `json:"captcha"`
			} `json:"configs"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("Échec d'analyse de la configuration captcha : %w", err)
	}
	if body.Code != 0 {
		return nil, fmt.Errorf("Code métier %d de l'interface de configuration captcha : %s", body.Code, body.Msg)
	}
	c := body.Data.Configs.Captcha
	cc := &CaptchaConfig{Enabled: c.Enabled, Region: c.Region, Prefix: c.Prefix, SceneID: c.SceneID}

	s.mu.Lock()
	s.config = cc
	s.configAt = time.Now()
	s.mu.Unlock()
	log.Printf("[captcha] config: enabled=%v region=%s prefix=%s scene=%s", cc.Enabled, cc.Region, cc.Prefix, cc.SceneID)
	return cc, nil
}

// ---- Résolution via navigateur rod ----

// findRealBrowser localise le vrai Chrome/Edge local (le Chromium embarqué est détecté par l'anti-fraude Aliyun)
func findRealBrowser() string {
	if runtime.GOOS != "windows" {
		for _, p := range []string{
			"/usr/bin/google-chrome", "/usr/bin/chromium-browser",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	candidates := []string{
		filepath.Join(programFiles, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(localAppData, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(programFiles, `Microsoft\Edge\Application\msedge.exe`),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// solveWithBrowser lance un navigateur pour effectuer une résolution.
// Tout chemin d'échec garantit le recyclage du processus navigateur lancé (évite la paralysie en cascade par verrou de profil).
func (s *CaptchaService) solveWithBrowser(cc *CaptchaConfig, headless bool, a *Account) (param string, err error) {
	bin := findRealBrowser()
	l := launcher.New().
		Headless(headless).
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-blink-features", "AutomationControlled").
		Set("lang", "zh-CN").
		Set("user-agent", captchaChromeUA)
	if bin != "" {
		l = l.Bin(bin)
	} else {
		log.Printf("[captcha] real Chrome/Edge not found, using rod managed browser (may be flagged)")
	}
	// Configuration navigateur persistante : conserve les cookies anti-fraude Aliyun pour éviter d'être vu comme un nouvel appareil à chaque résolution
	if profileDir := browserProfileDir(); profileDir != "" {
		l = l.UserDataDir(profileDir)
	}
	// Passe par le proxy de sortie du groupe de comptes (même IP que les requêtes amont, évite une incohérence anti-fraude)
	if proxyURL := captchaProxyHook(a); proxyURL != "" {
		l = l.Proxy(proxyURL)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return "", fmt.Errorf("Échec du démarrage du navigateur : %w", err)
	}
	// Enregistre immédiatement un recyclage de secours après un Launch réussi : tout échec de Connect ou ultérieur tue le processus
	killed := false
	defer func() {
		if !killed {
			l.Kill()
		}
	}()

	browser := rod.New().ControlURL(controlURL)
	if err = browser.Connect(); err != nil {
		return "", fmt.Errorf("Échec de connexion au navigateur : %w", err)
	}
	// Connect réussi : le recyclage (processus inclus) est confié à browser.Close, le Kill de secours est annulé
	defer func() {
		killed = true
		browser.Close()
	}()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "https://zcode.z.ai/"})
	if err != nil {
		return "", fmt.Errorf("Échec de l'ouverture de la page : %w", err)
	}
	defer page.Close()
	if err = page.WaitLoad(); err != nil {
		log.Printf("[captcha] wait load: %v", err)
	}

	// Expose le callback : JS window.__onCaptcha(jsonString) → canal Go
	events := make(chan map[string]interface{}, 8)
	if _, err = page.Expose("__onCaptcha", func(j gson.JSON) (interface{}, error) {
		payload := j.Str()
		var m map[string]interface{}
		if json.Unmarshal([]byte(payload), &m) == nil {
			select {
			case events <- m:
			default:
			}
		}
		return nil, nil
	}); err != nil {
		return "", fmt.Errorf("Échec de l'exposition du callback : %w", err)
	}

	// Injecte la page captcha
	html := captchaHTML(cc.SceneID, cc.Region, cc.Prefix)
	if err = page.SetDocumentContent(html); err != nil {
		return "", fmt.Errorf("Échec de l'injection de la page : %w", err)
	}

	deadline := time.After(captchaSolveTimeout)
	for {
		select {
		case ev := <-events:
			name, _ := ev["event"].(string)
			switch name {
			case "success":
				if p, ok := ev["param"].(string); ok && p != "" {
					return p, nil
				}
				return "", fmt.Errorf("l'événement success ne contient pas de param")
			case "fail":
				reason, _ := ev["reason"].(string)
				return "", fmt.Errorf("Échec de la vérification : %s", reason)
			case "error":
				reason, _ := ev["reason"].(string)
				return "", fmt.Errorf("Erreur SDK : %s", reason)
			case "starterr":
				msg, _ := ev["message"].(string)
				return "", fmt.Errorf("Exception au démarrage : %s", msg)
			}
		case <-deadline:
			return "", fmt.Errorf("Délai de résolution dépassé (%v)", captchaSolveTimeout)
		}
	}
}

// captchaProxyHook injecté par main : renvoie l'URL du proxy de sortie du groupe de comptes
var captchaProxyHook = func(a *Account) string { return "" }

// browserProfileHook injecté par main : renvoie le répertoire de configuration navigateur persistant
var browserProfileHook = func() string { return "" }

func browserProfileDir() string {
	dir := browserProfileHook()
	if dir == "" {
		return ""
	}
	os.MkdirAll(dir, 0755)
	return dir
}
