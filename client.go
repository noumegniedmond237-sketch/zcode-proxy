package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---- Usurpation d'identité du client desktop ZCode ----
// Portage de zai_headers_with_version de zcode-switch quota.rs :
// Les interfaces de facturation, d'activités et de chat partagent les mêmes en-têtes d'identification.

const (
	zcodeOrigin       = "https://zcode.z.ai"
	zcodeLang         = "zh-CN"
	zcodeChannel      = "stable"
	fallbackAppVer    = "3.11.2"
	screenResolution  = "2560x1440"
	anthropicVersionH = "2023-06-01"
)

var (
	clientInfoOnce sync.Once
	cachedPlatform string
	cachedTZ       string
	cachedOSVer    string
	cachedOSCat    string

	// Cache des clients HTTP amont (réutilisation du pool de connexions)
	clientCache sync.Map
)

// ClientPlatform renvoie l'identifiant de plateforme sous forme "win32-x64"
func ClientPlatform() string {
	clientInfoOnce.Do(initClientInfo)
	return cachedPlatform
}

// clientTimezoneValue fuseau horaire actuel (nom IANA)
func clientTimezoneValue() string {
	clientInfoOnce.Do(initClientInfo)
	return cachedTZ
}

// osCategoryValue catégorie d'OS (windows/darwin/linux)
func osCategoryValue() string {
	clientInfoOnce.Do(initClientInfo)
	return cachedOSCat
}

func initClientInfo() {
	osName := NodePlatform()
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	}
	cachedPlatform = osName + "-" + arch
	cachedOSCat = runtime.GOOS // windows / darwin / linux
	cachedTZ = detectTimezone()
	cachedOSVer = detectOSVersion()
}

// detectTimezone Windows mappe via tzutil, les autres plateformes lisent /etc/localtime
func detectTimezone() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tzutil", "/g").Output()
		if err == nil {
			switch strings.TrimSpace(string(out)) {
			case "China Standard Time", "China Daylight Time":
				return "Asia/Shanghai"
			case "Singapore Standard Time":
				return "Asia/Singapore"
			case "Tokyo Standard Time":
				return "Asia/Tokyo"
			case "UTC":
				return "UTC"
			}
		}
		return "Asia/Shanghai"
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		if tz := strings.TrimSpace(string(b)); tz != "" {
			return tz
		}
	}
	return "UTC"
}

// detectOSVersion Windows lit le registre CurrentBuildNumber → "10.0.x"
func detectOSVersion() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "CurrentBuildNumber").Output()
	if err != nil {
		return "10.0.19044"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "CurrentBuildNumber") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return "10.0." + fields[len(fields)-1]
			}
		}
	}
	return "10.0.19044"
}

// DetectZCodeAppVersion détecte la version installée de ZCode via le registre de désinstallation
// Repli sur la version interne par défaut si introuvable.
func DetectZCodeAppVersion() string {
	if runtime.GOOS != "windows" {
		return fallbackAppVer
	}
	hives := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	for _, hive := range hives {
		out, err := exec.Command("reg", "query", hive, "/s").Output()
		if err != nil {
			continue
		}
		var name, ver string
		for _, line := range strings.Split(string(out), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "HKEY_") {
				if isZcodeDisplayName(name) && ver != "" {
					return normalizeVersion(ver)
				}
				name, ver = "", ""
				continue
			}
			// Format de ligne : "    DisplayName    REG_SZ    ZCode 3.11.2"
			fields := strings.Fields(l)
			if len(fields) < 3 {
				continue
			}
			switch fields[0] {
			case "DisplayName":
				name = strings.Join(fields[2:], " ")
			case "DisplayVersion":
				ver = fields[len(fields)-1]
			}
		}
		if isZcodeDisplayName(name) && ver != "" {
			return normalizeVersion(ver)
		}
	}
	return fallbackAppVer
}

func stripPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return strings.TrimPrefix(s, prefix), true
	}
	return "", false
}

func isZcodeDisplayName(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "zcode") && !strings.Contains(l, "switch")
}

func normalizeVersion(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2]
	}
	return v
}

// ClientIdentity identité client d'une requête (version + appareil + ID de requête)
type ClientIdentity struct {
	AppVersion string
	DeviceMid  string
	RequestID  string
}

// NewClientIdentity construit l'identité ; lit telemetry-state.json si deviceMid est vide
func NewClientIdentity(appVersion, deviceMid string) ClientIdentity {
	if deviceMid == "" {
		deviceMid = LocalDeviceMid()
	}
	return ClientIdentity{AppVersion: appVersion, DeviceMid: deviceMid, RequestID: uuid.NewString()}
}

// LocalDeviceMid lit le deviceMid du client ZCode local
func LocalDeviceMid() string {
	p := LocalTelemetryPath()
	if p == "" {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var v struct {
		DeviceMid string `json:"deviceMid"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	return v.DeviceMid
}

// ZaiClientHeaders génère l'ensemble des en-têtes client pour les interfaces zcode.z.ai
func ZaiClientHeaders(id ClientIdentity) map[string]string {
	clientInfoOnce.Do(initClientInfo)
	h := map[string]string{
		"User-Agent":         "ZCode/" + id.AppVersion,
		"HTTP-Referer":       zcodeOrigin,
		"X-Title":            "Z Code@electron",
		"X-ZCode-App-Version": id.AppVersion,
		"X-Platform":         cachedPlatform,
		"X-Release-Channel":  zcodeChannel,
		"X-Client-Language":  zcodeLang,
		"X-Client-Timezone":  cachedTZ,
		"X-Os-Category":      cachedOSCat,
		"x-request-id":       id.RequestID,
		"Content-Type":       "application/json",
	}
	if cachedOSVer != "" {
		h["X-Os-Version"] = cachedOSVer
	}
	if id.DeviceMid != "" {
		h["X-Device-Mid"] = id.DeviceMid
	}
	return h
}

// ---- Usine de clients HTTP (proxy de groupe + empreinte utls) ----

// ProxyURLForNode convertit un nœud proxy en chaîne URL
func ProxyURLForNode(n *ProxyNode) string {
	if n == nil || n.Host == "" {
		return ""
	}
	scheme := n.Type
	if scheme == "" {
		scheme = "socks5"
	}
	auth := ""
	if n.Username != "" {
		auth = url.UserPassword(n.Username, n.Password).String() + "@"
	}
	return fmt.Sprintf("%s://%s%s:%d", scheme, auth, n.Host, n.Port)
}

// NewUpstreamHTTPClient client TLS de la bibliothèque standard (avec HTTP/2)
func NewUpstreamHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      32,
		IdleConnTimeout:   90 * time.Second,
	}
	applyProxy(transport, proxyURL)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Ne pas suivre les redirections : défis WAF / redirections traités explicitement
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewFingerprintHTTPClient client avec empreinte utls (HTTP/1.1)
func NewFingerprintHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	fp := fingerprintHook()
	dialer := &net.Dialer{Timeout: 30 * time.Second}

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		raw, err := dialRaw(ctx, dialer, proxyURL, network, addr)
		if err != nil {
			return nil, err
		}
		return utlsHandshake(ctx, raw, host, fp)
	}

	transport := &http.Transport{
		DialContext:     dialer.DialContext,
		DialTLSContext:  dialTLS,
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{}, // Désactive h2
		MaxIdleConns:    32,
		IdleConnTimeout: 90 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ClientForURL choisit le client selon l'hôte : zcode.z.ai -> empreinte utls ; autres -> stdlib h2
func ClientForURL(proxyURL, urlStr string, timeout time.Duration) *http.Client {
	fp := fingerprintHook()
	isZcode := strings.Contains(urlStr, "zcode.z.ai")
	// La clé de cache inclut le type d'hôte
	key := fmt.Sprintf("%s|%s|%s|%s|%v", proxyURL, fp.Mode, fp.JA3, timeout, isZcode)
	if v, ok := clientCache.Load(key); ok {
		return v.(*http.Client)
	}
	var c *http.Client
	if isZcode {
		c = NewFingerprintHTTPClient(proxyURL, timeout)
	} else {
		c = NewUpstreamHTTPClient(proxyURL, timeout)
	}
	actual, _ := clientCache.LoadOrStore(key, c)
	return actual.(*http.Client)
}

// CloseIdleClients ferme et vide tous les clients amont mis en cache
func CloseIdleClients() {
	clientCache.Range(func(k, v interface{}) bool {
		v.(*http.Client).CloseIdleConnections()
		clientCache.Delete(k)
		return true
	})
}

// applyProxy configure le proxy sur le transport standard
func applyProxy(transport *http.Transport, proxyURL string) {
	if proxyURL == "" {
		return
	}
	if u, err := url.Parse(proxyURL); err == nil {
		switch u.Scheme {
		case "socks5", "socks5h":
			if dialer, derr := Socks5Dialer(u); derr == nil {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.(proxyContextDialer).DialContext(ctx, network, addr)
				}
			}
		default:
			transport.Proxy = http.ProxyURL(u)
		}
	}
}

// dialRaw établit une connexion TCP brute vers l'adresse cible (via proxy ou directe)
func dialRaw(ctx context.Context, dialer *net.Dialer, proxyURL, network, addr string) (net.Conn, error) {
	if proxyURL == "" {
		return dialer.DialContext(ctx, network, addr)
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return dialer.DialContext(ctx, network, addr)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		sd, err := Socks5Dialer(u)
		if err != nil {
			return nil, err
		}
		return sd.Dial(network, addr)
	default: // Proxy http/https : tunnel CONNECT
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}
		if err := httpConnectTunnel(ctx, conn, addr, u); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// httpConnectTunnel envoie la commande CONNECT au proxy HTTP et attend le statut 200
func httpConnectTunnel(ctx context.Context, conn net.Conn, addr string, proxyURL *url.URL) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Échec CONNECT proxy : HTTP %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("Données superflues dans la réponse CONNECT")
	}
	return nil
}
