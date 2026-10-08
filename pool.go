package main

import (
	"log"
	"math/rand"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ---- Pool de comptes : machine d'état + stratégie de sélection + boucle de rafraîchissement ----
//
// Statuts (alignés avec models.py de zcode2api, avec inactive = forfait non activé) :
//   active    Normal, éligible à la rotation
//   exhausted Quota épuisé (402 / remaining=0), inéligible jusqu'au rafraîchissement
//   cooling   En refroidissement après limitation (429), redevient éligible à l'échéance de cooling_until
//   invalid   Identifiants invalides (401/403), intervention manuelle requise
//   disabled  Désactivé manuellement
//   inactive  Coding Plan / Start Plan non activé (peut tenter la procédure d'activation)

const (
	StatusActive    = "active"
	StatusExhausted = "exhausted"
	StatusCooling   = "cooling"
	StatusInvalid   = "invalid"
	StatusDisabled  = "disabled"
	StatusInactive  = "inactive"
)

// Stratégies de sélection
const (
	StrategyRandom     = "random"
	StrategyRoundRobin = "round_robin"
	StrategyBestQuota  = "best_quota"
)

// AccountPool pool de comptes
type AccountPool struct {
	db         *DB
	cfg        *FileConfig
	appVersion string

	mu       sync.Mutex
	rotation map[string]int // "group|provider" -> curseur round-robin

	refreshFn func(a *Account) error // Fonction de rafraîchissement injectée par ZCodeAPI
	stopCh    chan struct{}
	stopOnce  sync.Once
}

// NewAccountPool crée le pool de comptes
func NewAccountPool(db *DB, cfg *FileConfig, appVersion string) *AccountPool {
	return &AccountPool{
		db:         db,
		cfg:        cfg,
		appVersion: appVersion,
		rotation:   make(map[string]int),
		stopCh:     make(chan struct{}),
	}
}

// SetQuotaFetcher injecte l'implémentation de rafraîchissement des quotas
func (p *AccountPool) SetQuotaFetcher(fn func(a *Account) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshFn = fn
}

// Start lance la boucle d'actualisation en arrière-plan
func (p *AccountPool) Start() {
	go p.refreshLoop()
}

// Stop arrête la boucle d'arrière-plan
func (p *AccountPool) Stop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
}

func (p *AccountPool) refreshLoop() {
	// Attendre 5 secondes au démarrage (laisser le service HTTP s'initialiser)
	select {
	case <-p.stopCh:
		return
	case <-time.After(5 * time.Second):
	}
	for {
		interval := p.refreshInterval()
		if interval > 0 {
			p.refreshAll()
		}
		select {
		case <-p.stopCh:
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

func (p *AccountPool) refreshInterval() int {
	v, err := p.db.GetSetting("quota_refresh_interval")
	if err != nil || v == "" {
		return 60 // Non configuré : 60s par défaut
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 60
	}
	if n < 0 {
		return 60
	}
	return n // 0 explicite = désactive l'actualisation en arrière-plan
}

// refreshAll actualise les quotas de tous les comptes activés (concurrence 4, délai aléatoire 1-3s)
func (p *AccountPool) refreshAll() {
	p.mu.Lock()
	fn := p.refreshFn
	p.mu.Unlock()
	if fn == nil {
		return
	}
	accounts, err := p.db.ListAccounts("")
	if err != nil {
		log.Printf("[pool] list accounts: %v", err)
		return
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, a := range accounts {
		if !a.Enabled || a.Status == StatusDisabled || a.Status == StatusInvalid {
			continue
		}
		if a.ZCodeJWT == "" && a.APIKey == "" {
			continue
		}
		// Les comptes en refroidissement sont ignorés (récupération naturelle à l'échéance)
		if a.Status == StatusCooling && a.CoolingUntil > time.Now().Unix() {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(acc *Account) {
			defer wg.Done()
			defer func() { <-sem }()
			// Délai aléatoire de 0-2s par compte pour simuler un comportement humain
			time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
			if err := fn(acc); err != nil {
				log.Printf("[pool] refresh quota %s: %v", acc.Email, err)
			}
		}(a)
	}
	wg.Wait()
}

// RefreshOne actualise manuellement le quota d'un seul compte (déclenché par l'API)
func (p *AccountPool) RefreshOne(a *Account) error {
	p.mu.Lock()
	fn := p.refreshFn
	p.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(a)
}

// ---- Éligibilité des comptes (portage de is_selectable de models.py) ----

func accountSelectable(a *Account, now int64) bool {
	if !a.Enabled || a.Status == StatusDisabled || a.Status == StatusInvalid ||
		a.Status == StatusExhausted || a.Status == StatusInactive {
		return false
	}
	if a.Status == StatusCooling {
		// cooling_until<=0 (données historiques/manuelles) considéré comme expiré
		return a.CoolingUntil <= 0 || now >= a.CoolingUntil
	}
	return true
}

// EffectiveStatus état effectif prenant en compte l'expiration du refroidissement
func EffectiveStatus(a *Account) string {
	if a.Status == StatusCooling && a.CoolingUntil > 0 && time.Now().Unix() >= a.CoolingUntil {
		return StatusActive
	}
	return a.Status
}

// ---- Sélection de compte ----

// Select choisit un compte selon la stratégie. group vide = tout groupe ; skip = IDs déjà tentés.
func (p *AccountPool) Select(provider, group string, skip map[int64]bool) *Account {
	accounts, err := p.db.ListAccounts("")
	if err != nil {
		log.Printf("[pool] select list: %v", err)
		return nil
	}
	now := time.Now().Unix()
	var pool []*Account
	for _, a := range accounts {
		if a.Provider != provider {
			continue
		}
		if group != "" && a.AccountGroup != group {
			continue
		}
		if skip[a.ID] {
			continue
		}
		if !accountSelectable(a, now) {
			continue
		}
		// Doit avoir un identifiant disponible
		if a.ZCodeJWT == "" && a.APIKey == "" {
			continue
		}
		pool = append(pool, a)
	}
	if len(pool) == 0 {
		return nil
	}

	strategy, _ := p.db.GetSetting("selection_strategy")
	switch strategy {
	case StrategyRandom:
		return pool[rand.Intn(len(pool))]
	case StrategyBestQuota:
		// Priorité au quota restant le plus élevé ; quota inconnu (0) en dernier
		sort.SliceStable(pool, func(i, j int) bool {
			return pool[i].Remaining > pool[j].Remaining
		})
		return pool[0]
	default: // round_robin
		p.mu.Lock()
		defer p.mu.Unlock()
		key := group + "|" + provider
		idx := p.rotation[key] % len(pool)
		a := pool[idx]
		p.rotation[key] = (idx + 1) % len(pool)
		return a
	}
}

// ---- Transitions d'état ----

// MarkExhausted quota épuisé
func (p *AccountPool) MarkExhausted(a *Account, reason string) {
	a.Status = StatusExhausted
	a.LastError = reason
	p.db.SetAccountStatus(a.ID, StatusExhausted, reason, 0)
	log.Printf("[pool] account %s -> exhausted: %s", a.Email, reason)
}

// MarkCooling refroidissement suite à une limitation (60s par défaut)
func (p *AccountPool) MarkCooling(a *Account, reason string, seconds int) {
	if seconds <= 0 {
		seconds = 60
	}
	until := time.Now().Unix() + int64(seconds)
	a.Status = StatusCooling
	a.CoolingUntil = until
	a.LastError = reason
	p.db.SetAccountStatus(a.ID, StatusCooling, reason, until)
	log.Printf("[pool] account %s -> cooling %ds: %s", a.Email, seconds, reason)
}

// MarkInvalid identifiants expirés ou invalides
func (p *AccountPool) MarkInvalid(a *Account, reason string) {
	a.Status = StatusInvalid
	a.LastError = reason
	p.db.SetAccountStatus(a.ID, StatusInvalid, reason, 0)
	log.Printf("[pool] account %s -> invalid: %s", a.Email, reason)
}

// MarkInactive forfait non activé
func (p *AccountPool) MarkInactive(a *Account, reason string) {
	a.Status = StatusInactive
	a.LastError = reason
	p.db.SetAccountStatus(a.ID, StatusInactive, reason, 0)
	log.Printf("[pool] account %s -> inactive: %s", a.Email, reason)
}

// MarkUsed utilisation réussie (cooling/exhausted redevient active)
func (p *AccountPool) MarkUsed(a *Account) {
	a.UseCount++
	a.LastUsedAt = time.Now().Unix()
	if a.Status == StatusCooling || a.Status == StatusExhausted {
		a.Status = StatusActive
		a.CoolingUntil = 0
	}
	p.db.TouchAccountUse(a.ID)
}

// MarkFailed incrémente le compteur d'échecs
func (p *AccountPool) MarkFailed(a *Account, reason string) {
	a.FailCount++
	a.LastError = reason
	p.db.BumpAccountFail(a.ID, reason)
}

// CoolingInfo renvoie le délai de récupération et la raison du compte le plus proche pour 503
func (p *AccountPool) CoolingInfo(provider, group string) (int64, string) {
	accounts, err := p.db.ListAccounts("")
	if err != nil {
		return 0, ""
	}
	now := time.Now().Unix()
	var until int64
	reason := ""
	for _, a := range accounts {
		if provider != "" && a.Provider != provider {
			continue
		}
		if group != "" && a.AccountGroup != group {
			continue
		}
		if a.Status == StatusCooling && a.CoolingUntil > now {
			if until == 0 || a.CoolingUntil < until {
				until = a.CoolingUntil
				reason = a.LastError
			}
		}
	}
	return until, reason
}

// SelectableCount renvoie le nombre de comptes éligibles actuels (tableau de bord)
func (p *AccountPool) SelectableCount(provider string) int {
	accounts, err := p.db.ListAccounts("")
	if err != nil {
		return 0
	}
	now := time.Now().Unix()
	n := 0
	for _, a := range accounts {
		if provider != "" && a.Provider != provider {
			continue
		}
		if accountSelectable(a, now) && (a.ZCodeJWT != "" || a.APIKey != "") {
			n++
		}
	}
	return n
}
