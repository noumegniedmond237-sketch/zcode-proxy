package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ---- Proxy de sortie : dialer SOCKS5 / résolution de proxy par groupe / test de santé / détection système ----

type proxyContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Socks5Dialer crée un dialer supportant le context à partir de socks5://[user:pass@]host:port
func Socks5Dialer(u *url.URL) (proxy.Dialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}
	forward := &net.Dialer{Timeout: 15 * time.Second}
	return proxy.SOCKS5("tcp", u.Host, auth, forward)
}

// EgressProxy résolveur de proxy de sortie : lié au groupe -> par défaut -> global -> direct
type EgressProxy struct {
	db *DB
}

// NewEgressProxy crée le résolveur
func NewEgressProxy(db *DB) *EgressProxy {
	return &EgressProxy{db: db}
}

// ProxyURLForAccount résout l'URL du proxy de sortie pour le compte (vide = direct)
func (e *EgressProxy) ProxyURLForAccount(a *Account) string {
	if a == nil {
		return e.GlobalProxyURL()
	}
	node, err := e.db.ProxyNodeForGroup(a.AccountGroup)
	if err == nil && node != nil {
		if u := ProxyURLForNode(node); u != "" {
			return u
		}
	}
	return e.GlobalProxyURL()
}

// GlobalProxyURL paramètre de proxy amont global (settings KV upstream_proxy)
func (e *EgressProxy) GlobalProxyURL() string {
	v, _ := e.db.GetSetting("upstream_proxy")
	return strings.TrimSpace(v)
}

// HTTPClientForAccount construit le client HTTP selon le groupe du compte
func (e *EgressProxy) HTTPClientForAccount(a *Account, timeout time.Duration) *http.Client {
	return NewUpstreamHTTPClient(e.ProxyURLForAccount(a), timeout)
}

// ---- Test de santé : IP de sortie ----

var exitIPAPIs = []string{
	"https://api.ipify.org/?format=json",
	"https://ipinfo.io/json",
}

// TestProxyExitIP teste la connectivité du proxy et renvoie l'IP de sortie (proxyURL vide = connexion directe)
func TestProxyExitIP(proxyURL string) (ip string, elapsed time.Duration, err error) {
	client := NewUpstreamHTTPClient(proxyURL, 15*time.Second)
	start := time.Now()
	for _, api := range exitIPAPIs {
		resp, e := client.Get(api)
		if e != nil {
			err = e
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var v map[string]interface{}
		if json.Unmarshal(body, &v) == nil {
			if s, ok := v["ip"].(string); ok && s != "" {
				return s, time.Since(start), nil
			}
		}
	}
	if err == nil {
		err = fmt.Errorf("Impossible d'obtenir l'IP de sortie")
	}
	return "", time.Since(start), err
}

// ---- Détection du proxy système (Registre Windows) ----

// DetectSystemProxy lit les paramètres de proxy du système Windows
func DetectSystemProxy() (enabled bool, proxyURL string) {
	if runtime.GOOS != "windows" {
		for _, env := range []string{"http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"} {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				return true, v
			}
		}
		return false, ""
	}
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable").Output()
	if err != nil || !strings.Contains(string(out), "0x1") {
		return false, ""
	}
	out2, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer").Output()
	if err != nil {
		return false, ""
	}
	server := ""
	for _, line := range strings.Split(string(out2), "\n") {
		if strings.Contains(line, "ProxyServer") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				server = fields[len(fields)-1]
			}
		}
	}
	if server == "" {
		return false, ""
	}
	// ProxyServer peut être "host:port" ou "http=...;https=...;socks=..."
	if strings.Contains(server, "=") {
		parts := map[string]string{}
		for _, p := range strings.Split(server, ";") {
			if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
				parts[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		server = parts["https"]
		if server == "" {
			server = parts["http"]
		}
		if server == "" {
			for _, v := range parts {
				server = v
				break
			}
		}
	}
	if server != "" && !strings.Contains(server, "://") {
		server = "http://" + server
	}
	return true, server
}

// ---- Détection des ports de proxy locaux ----

var probePorts = []int{7897, 7890, 7891, 7899, 1080, 10808, 2080, 8889, 8118}

var portLabels = map[int]string{
	7897:  "Port mixte Clash Verge (défaut fréquent)",
	7890:  "Port mixte Clash (défaut fréquent)",
	7891:  "Port HTTP Clash",
	7899:  "Port secondaire Clash Verge",
	1080:  "Port générique SOCKS5",
	10808: "Port SOCKS v2rayN",
	2080:  "Port mixte sing-box",
	8889:  "Port proxy HTTP générique",
	8118:  "Port HTTP Privoxy",
}

// ProbeLocalProxyPorts teste simultanément les ports courants de proxy locaux
func ProbeLocalProxyPorts() []map[string]interface{} {
	type result struct {
		port int
		open bool
	}
	results := make(chan result, len(probePorts))
	for _, p := range probePorts {
		go func(port int) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			results <- result{port, err == nil}
		}(p)
	}
	var out []map[string]interface{}
	byPort := map[int]bool{}
	for i := 0; i < len(probePorts); i++ {
		r := <-results
		byPort[r.port] = r.open
	}
	for _, p := range probePorts {
		if byPort[p] {
			label := portLabels[p]
			if label == "" {
				label = "Port proxy local"
			}
			out = append(out, map[string]interface{}{
				"url":   fmt.Sprintf("http://127.0.0.1:%d", p),
				"port":  p,
				"label": label,
			})
		}
	}
	return out
}

// MaskProxyURL masque l'URL du proxy (cache le nom d'utilisateur et mot de passe)
func MaskProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	username := u.User.Username()
	masked := "***"
	if len(username) >= 2 {
		masked = username[:2] + "***"
	}
	u.User = url.User(masked)
	return u.String()
}
