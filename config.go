package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---- Configuration fichier JSON (config/config.json, rechargement à chaud) ----
// Les options modifiables à l'exécution (stratégie/proxy/empreinte/mot de passe/APIKey) sont stockées dans la table SQLite settings ;
// ici uniquement la configuration de déploiement : adresse d'écoute, endpoints amont, liste de modèles, version client.

// UpstreamURLs endpoints amont (surchageables via config.json, pratique pour les tests hors ligne)
type UpstreamURLs struct {
	Zai         string `json:"zai"`          // canal gratuit JWT zcode.z.ai
	ZaiFallback string `json:"zai_fallback"` // canal API Key api.z.ai
	Bigmodel    string `json:"bigmodel"`     // open.bigmodel.cn
}

// FileConfig structure de config.json
type FileConfig struct {
	ListenAddr string       `json:"listen_addr"`
	AppVersion string       `json:"app_version"` // Version client ZCode usurpée, vide = détection auto via registre
	Models     []string     `json:"models"`      // liste de modèles publiée sur /v1/models
	Upstream   UpstreamURLs `json:"upstream"`

	configDir string
	mu        sync.RWMutex
}

// DefaultUpstream endpoints par défaut (alignés avec settings.py de zcode2api)
var DefaultUpstream = UpstreamURLs{
	Zai:         "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages",
	ZaiFallback: "https://api.z.ai/api/anthropic/v1/messages",
	Bigmodel:    "https://open.bigmodel.cn/api/anthropic/v1/messages",
}

// DefaultModels liste de modèles par défaut (casse sensible côté amont, noms officiels ici)
var DefaultModels = []string{
	"GLM-5.3", "GLM-5.2", "GLM-5-Turbo", "GLM-4.7", "GLM-4.6",
	"GLM-4.5", "GLM-4.5-Air", "GLM-4.5V", "GLM-4.5-Flash",
}

// LoadFileConfig charge le dossier de configuration ; si absent, valeurs par défaut + écriture sur disque
func LoadFileConfig(configDir string) (*FileConfig, error) {
	c := &FileConfig{configDir: configDir}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *FileConfig) reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.configDir, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Première exécution : écrire la configuration par défaut
			c.ListenAddr = "127.0.0.1:8687"
			c.AppVersion = ""
			c.Models = DefaultModels
			c.Upstream = DefaultUpstream
			c.writeDefaultLocked(path)
			return nil
		}
		return fmt.Errorf("read config.json: %w", err)
	}
	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parse config.json: %w", err)
	}
	c.ListenAddr = fc.ListenAddr
	c.AppVersion = fc.AppVersion
	c.Models = fc.Models
	c.Upstream = fc.Upstream
	// Compléter les valeurs par défaut
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8687"
	}
	if len(c.Models) == 0 {
		c.Models = DefaultModels
	}
	if c.Upstream.Zai == "" {
		c.Upstream.Zai = DefaultUpstream.Zai
	}
	if c.Upstream.ZaiFallback == "" {
		c.Upstream.ZaiFallback = DefaultUpstream.ZaiFallback
	}
	if c.Upstream.Bigmodel == "" {
		c.Upstream.Bigmodel = DefaultUpstream.Bigmodel
	}
	return nil
}

func (c *FileConfig) writeDefaultLocked(path string) {
	os.MkdirAll(filepath.Dir(path), 0755)
	// Sérialisation via struct indépendante, évite de copier le mutex de FileConfig
	out := struct {
		ListenAddr string       `json:"listen_addr"`
		AppVersion string       `json:"app_version"`
		Models     []string     `json:"models"`
		Upstream   UpstreamURLs `json:"upstream"`
	}{
		ListenAddr: c.ListenAddr,
		AppVersion: c.AppVersion,
		Models:     c.Models,
		Upstream:   c.Upstream,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[config] write default config.json: %v", err)
	}
}

// StartHotReload rechargement à chaud périodique
func (c *FileConfig) StartHotReload(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := c.reload(); err != nil {
				log.Printf("[config] hot reload failed: %v", err)
			}
		}
	}()
}

// GetListenAddr lecture thread-safe
func (c *FileConfig) GetListenAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ListenAddr
}

// GetUpstream lecture thread-safe
func (c *FileConfig) GetUpstream() UpstreamURLs {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Upstream
}

// GetModels lecture thread-safe
func (c *FileConfig) GetModels() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.Models...)
}

// GetAppVersion version configurée (vide = détection auto par l'appelant)
func (c *FileConfig) GetAppVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AppVersion
}
