package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

func main() {
	configDir := flag.String("config", "config", "config directory path")
	dbPath := flag.String("db", "data/zcode.db", "SQLite database path")
	flag.Parse()

	absDir, err := filepath.Abs(*configDir)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}
	os.MkdirAll(absDir, 0755)

	cfg, err := LoadFileConfig(absDir)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	log.Printf("[main] config dir: %s, models=%d", absDir, len(cfg.GetModels()))

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		log.Fatalf("resolve db path: %v", err)
	}
	os.MkdirAll(filepath.Dir(absDBPath), 0755)
	db, err := NewDB(absDBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	log.Printf("[main] database: %s", absDBPath)

	cfg.StartHotReload(30 * time.Second)

	// Version client usurpée : priorité config, puis détection registre, puis défaut interne
	appVersion := cfg.GetAppVersion()
	if appVersion == "" {
		appVersion = DetectZCodeAppVersion()
	}
	log.Printf("[main] zcode app version: %s", appVersion)

	// Pool de comptes (machine d'état + stratégie de sélection + boucle de rafraîchissement)
	pool := NewAccountPool(db, cfg, appVersion)
	pool.Start()

	// Hook d'empreinte TLS (préréglages utls / JA3 personnalisé)
	fingerprintHook = func() TLSFingerprint {
		mode, _ := db.GetSetting("fingerprint")
		ja3, _ := db.GetSetting("custom_ja3")
		if mode == "" {
			mode = "chrome"
		}
		return TLSFingerprint{Mode: mode, JA3: ja3}
	}
	// Migration : l'ancienne base peut conserver une valeur hors table, repli sur chrome
	if cur, _ := db.GetSetting("fingerprint"); cur != "" && !isValidFingerprint(cur) {
		db.SetSetting("fingerprint", "chrome")
		log.Printf("[main] migrated invalid fingerprint setting %q -> chrome", cur)
	}

	// Service de résolution captcha (Alibaba Cloud sans trace, rod pilotant Chrome/Edge local)
	captcha := NewCaptchaService(cfg, db, appVersion)
	egress := NewEgressProxy(db)
	captchaProxyHook = func(a *Account) string { return egress.ProxyURLForAccount(a) }
	browserProfileHook = func() string {
		exe, _ := os.Executable()
		return filepath.Join(filepath.Dir(exe), "data", "browser-profile")
	}

	// Wrapper API amont (quota / activités / activation / relais de chat)
	zapi := NewZCodeAPI(cfg, db, pool, captcha, appVersion)

	// Gestion de connexion OAuth (callback loopback + collage manuel de secours)
	oauth := NewOAuthManager(db, zapi, cfg.GetListenAddr())

	// Gestion des comptes (import client local / import collage / rebascule)
	acctMgr := NewAccountManager(db, zapi, oauth)

	// Planificateur de tâches (cron)
	scheduler := NewCronScheduler(db, zapi)
	scheduler.Start()
	defer scheduler.Stop()

	// Authentification Web
	auth := NewAuthManager(db, os.Getenv("ZCODE_WEB_PASS"))

	// API REST d'administration
	apiServer := NewAPIServer(db, cfg, pool, zapi, oauth, acctMgr, scheduler, auth, captcha)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	// Points d'accès 2API
	mux.HandleFunc("/v1/messages", zapi.HandleMessages)
	mux.HandleFunc("/v1/messages/", zapi.HandleMessages)
	mux.HandleFunc("/v1/messages/count_tokens", zapi.HandleCountTokens)
	mux.HandleFunc("/v1/chat/completions", zapi.HandleChatCompletions)
	mux.HandleFunc("/v1/responses", zapi.HandleResponses)
	mux.HandleFunc("/v1/models", zapi.HandleModels)

	// Callback loopback OAuth (redirection navigateur après autorisation, sans authentification)
	mux.HandleFunc("/oauth/callback", oauth.HandleCallback)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "zcode-proxy"})
	})

	// Interface Web frontend
	webContent, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		log.Fatalf("read embedded web/index.html: %v", err)
	}
	mux.HandleFunc("/web", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(webContent)
	})
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("sub web fs: %v", err)
	}
	staticHandler := http.StripPrefix("/web/", http.FileServer(http.FS(webSub)))
	mux.HandleFunc("/web/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/web/static/") {
			// Revalidation forcée des ressources statiques
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			staticHandler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(webContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/web", http.StatusFound)
			return
		}
		// Renvoyer 404 pour les routes /api/* et /v1/* inconnues
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			writeAPIError(w, http.StatusNotFound, "not found: "+r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"service":"zcode-proxy","version":"1.0","endpoints":["/v1/messages","/v1/chat/completions","/v1/responses","/v1/models","/api/","/web","/health"]}`)
	})

	listenAddr := cfg.GetListenAddr()
	log.Printf("[main] zcode-proxy listening on http://%s", listenAddr)
	log.Printf("[main] web UI: http://%s/web", listenAddr)
	// Serveur explicite : ReadHeaderTimeout protège contre Slowloris ; pas de WriteTimeout pour le SSE
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           auth.Middleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
