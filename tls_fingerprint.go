package main

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// ---- Usurpation d'empreinte TLS (utls) ----
// Le client de bureau ZCode est un Electron (Chromium) ; l'empreinte ClientHello de crypto/tls par défaut de Go
// se distingue nettement et est facilement identifiée comme un programme automatique par le WAF ESA amont.
// On utilise utls pour imiter l'empreinte TLS d'un navigateur, avec presets et JA3 personnalisé.
// Usurpation d'empreinte TLS (utls) : imiter le ClientHello d'un navigateur pour réduire le score de caractéristiques machine.

// TLSFingerprint configuration d'empreinte actuellement active
type TLSFingerprint struct {
	Mode string `json:"mode"` // off|chrome|firefox|...|custom
	JA3  string `json:"ja3"`  // chaîne JA3 lorsque mode=custom
}

// tlsFingerprintPresets modes d'empreinte disponibles (liste déroulante du frontend)
var tlsFingerprintPresets = []struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
}{
	{"off", "Désactivé (empreinte par défaut de Go)", "Base"},
	{"randomized", "Empreinte aléatoire", "Base"},
	{"chrome", "Navigateur Chrome (dernière version automatique)", "Navigateurs"},
	{"chrome_100", "Chrome 100", "Navigateurs"},
	{"chrome_83", "Chrome 83 (fréquent sur les anciens Electron)", "Navigateurs"},
	{"firefox", "Navigateur Firefox (120)", "Navigateurs"},
	{"safari", "Navigateur Safari (16.0)", "Navigateurs"},
	{"edge", "Navigateur Edge (85)", "Navigateurs"},
	{"qq", "Navigateur QQ (11.1)", "Navigateurs"},
	{"q360", "Navigateur 360 (7.5)", "Navigateurs"},
	{"bun", "Bun.js (BoringSSL)", "Runtimes et outils"},
	{"node", "Node.js (OpenSSL)", "Runtimes et outils"},
	{"deno", "Deno (rustls)", "Runtimes et outils"},
	{"curl", "curl (OpenSSL)", "Runtimes et outils"},
	{"python", "Python requests (OpenSSL)", "Runtimes et outils"},
	{"okhttp", "OkHttp 3 (Android)", "Runtimes et outils"},
	{"golang", "Bibliothèque standard Go (crypto/tls)", "Runtimes et outils"},
	{"ios", "iOS Safari (14)", "Mobile"},
	{"android", "Android OkHttp (11)", "Mobile"},
	{"custom", "Empreinte JA3 personnalisée", "Personnalisé"},
}

// builtinJA3 empreintes JA3 publiques de clients non navigateur (aucun preset utls officiel, reconstruites via ClientHelloSpec)
var builtinJA3 = map[string]string{
	"bun":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
	"node":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
	"deno":   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0",
	"curl":   "769,49195-49196-49199-49200-52393-52392-158-159-49161-49162-49171-49172-51-57-47-53,0-11-10-13,23-24-25,0",
	"python": "769,49195-49196-49199-49200-52393-52392-158-159-49161-49162-49171-49172-51-57-47-53,0-11-10-16-13,23-24-25,0",
	"okhttp": "771,49199-49195-52393-49196-49200-49162-49161-52392-49171-49172-156-157-47-53,0-11-10-35-16-5-13-18-51-45-43-27-23-17,29-23-24,0",
}

// fingerprintHook injecté par main : renvoie la configuration d'empreinte courante
var fingerprintHook = func() TLSFingerprint { return TLSFingerprint{Mode: "chrome"} }

// isValidFingerprint indique si le mode est un preset valide (custom est également valide)
func isValidFingerprint(mode string) bool {
	if mode == "custom" || mode == "off" {
		return true
	}
	for _, p := range tlsFingerprintPresets {
		if p.ID == mode {
			return true
		}
	}
	if _, ok := builtinJA3[mode]; ok {
		return true
	}
	return false
}

func presetHelloID(mode string) (tls.ClientHelloID, bool) {
	switch mode {
	case "chrome":
		return tls.HelloChrome_Auto, true
	case "chrome_100":
		return tls.HelloChrome_100, true
	case "chrome_83":
		return tls.HelloChrome_83, true
	case "firefox":
		return tls.HelloFirefox_Auto, true
	case "safari":
		return tls.HelloSafari_Auto, true
	case "edge":
		return tls.HelloEdge_Auto, true
	case "qq":
		return tls.HelloQQ_Auto, true
	case "q360":
		return tls.Hello360_Auto, true
	case "ios":
		return tls.HelloIOS_Auto, true
	case "android":
		return tls.HelloAndroid_11_OkHttp, true
	case "randomized":
		return tls.HelloRandomized, true
	case "randomized_alpn":
		return tls.HelloRandomizedALPN, true
	case "golang":
		return tls.HelloGolang, true
	}
	return tls.HelloChrome_Auto, false
}

// utlsHandshake effectue la poignée de main TLS sur une connexion brute déjà établie, selon la configuration d'empreinte.
// rawConn peut être un TCP en direct ou une connexion tunnelisée via un proxy SOCKS5/HTTP.
func utlsHandshake(ctx context.Context, rawConn net.Conn, serverName string, fp TLSFingerprint) (net.Conn, error) {
	if fp.Mode == "" || fp.Mode == "off" {
		c := stdtls.Client(rawConn, &stdtls.Config{ServerName: serverName, MinVersion: stdtls.VersionTLS12})
		if err := c.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return c, nil
	}
	helloID, _ := presetHelloID(fp.Mode)
	uconn := tls.UClient(rawConn, &tls.Config{ServerName: serverName}, helloID)
	ja3Str := ""
	if fp.Mode == "custom" {
		ja3Str = strings.TrimSpace(fp.JA3)
	} else if builtin, ok := builtinJA3[fp.Mode]; ok {
		ja3Str = builtin
	}
	if ja3Str != "" {
		spec, err := ja3ToClientHelloSpec(ja3Str)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		uconn.ClientHelloID = tls.HelloCustom
		if err := uconn.ApplyPreset(spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("Empreinte invalide : %w", err)
		}
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

// ---- Analyse JA3 : chaîne JA3 → utls.ClientHelloSpec ----

func ja3ToClientHelloSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	ja3 = strings.TrimSpace(ja3)
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("JA3 doit comporter 5 segments (version,suites,extensions,courbes,formats)")
	}
	ciphers := parseU16List(parts[1])
	extIDs := parseU16List(parts[2])
	curves := parseU16List(parts[3])
	pointFmts := parseU8List(parts[4])

	spec := &tls.ClientHelloSpec{
		CipherSuites:       ciphers,
		CompressionMethods: []byte{0x00},
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
	}
	hasExt := func(id uint16) bool {
		for _, x := range extIDs {
			if x == id {
				return true
			}
		}
		return false
	}
	var exts []tls.TLSExtension
	exts = append(exts, &tls.SNIExtension{})
	for _, id := range extIDs {
		switch id {
		case 0:
		case 5:
			exts = append(exts, &tls.StatusRequestExtension{})
		case 10:
			exts = append(exts, &tls.SupportedCurvesExtension{Curves: toCurveIDs(curves)})
		case 11:
			exts = append(exts, &tls.SupportedPointsExtension{SupportedPoints: pointFmts})
		case 13:
			exts = append(exts, &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSigAlgs()})
		case 16:
			exts = append(exts, &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
		case 18:
			exts = append(exts, &tls.SCTExtension{})
		case 23:
			exts = append(exts, &tls.ExtendedMasterSecretExtension{})
		case 27:
			exts = append(exts, &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}})
		case 35:
			exts = append(exts, &tls.SessionTicketExtension{})
		case 43:
			exts = append(exts, &tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}})
		case 45:
			exts = append(exts, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}})
		case 51:
		case 65281:
			exts = append(exts, &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient})
		}
	}
	if hasExt(51) {
		exts = append(exts, &tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}})
	}
	spec.Extensions = exts
	return spec, nil
}

func toCurveIDs(v []uint16) []tls.CurveID {
	out := make([]tls.CurveID, len(v))
	for i, x := range v {
		out[i] = tls.CurveID(x)
	}
	return out
}

func defaultSigAlgs() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
		tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
		tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512,
		tls.ECDSAWithSHA1, tls.PKCS1WithSHA1,
	}
}

func parseU16List(s string) []uint16 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []uint16
	for _, p := range strings.Split(s, "-") {
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16); err == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

func parseU8List(s string) []uint8 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []uint8
	for _, p := range strings.Split(s, "-") {
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8); err == nil {
			out = append(out, uint8(n))
		}
	}
	return out
}
