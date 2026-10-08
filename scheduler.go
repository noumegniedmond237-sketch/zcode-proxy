package main

import (
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- Planificateur des plans d'activité ----
// Planificateur cron à 5 segments (min heure jour mois semaine) : déduplication à la minute + mutex par plan + délai anti-risque entre comptes.
// task_type: detect (détection d'activité) | claim (réclamation en un clic) | activate (activation du forfait)
// target_type: all_accounts | single_account | group
// Délai entre comptes delay_seconds + gigue aléatoire (anti-risque).

// PlanRunState état d'exécution en temps réel d'un plan (affichage de progression côté frontend)
type PlanRunState struct {
	PlanID         int64  `json:"plan_id"`
	PlanName       string `json:"plan_name"`
	TaskType       string `json:"task_type"`
	Total          int    `json:"total"`
	Done           int    `json:"done"`
	Success        int    `json:"success"`
	Fail           int    `json:"fail"`
	CurrentAccount string `json:"current_account"`
	StartedAt      string `json:"started_at"`
}

// CronScheduler planificateur cron
type CronScheduler struct {
	db   *DB
	zapi *ZCodeAPI

	stopCh  chan struct{}
	stopOnce sync.Once
	ticker  *time.Ticker
	runMu   sync.Mutex
	running map[int64]*PlanRunState

	execMu    sync.Mutex
	execLocks map[int64]*sync.Mutex // mutex d'exécution par plan (TryLock, si indisponible on saute ce tick)
}

// NewCronScheduler crée le planificateur
func NewCronScheduler(db *DB, zapi *ZCodeAPI) *CronScheduler {
	return &CronScheduler{
		db:        db,
		zapi:      zapi,
		stopCh:    make(chan struct{}),
		running:   make(map[int64]*PlanRunState),
		execLocks: make(map[int64]*sync.Mutex),
	}
}

// planLock renvoie le mutex au niveau du plan
func (s *CronScheduler) planLock(id int64) *sync.Mutex {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	if m, ok := s.execLocks[id]; ok {
		return m
	}
	m := &sync.Mutex{}
	s.execLocks[id] = m
	return m
}

// Start démarre le planificateur (vérification chaque minute)
func (s *CronScheduler) Start() {
	s.ticker = time.NewTicker(1 * time.Minute)
	go func() {
		log.Printf("[scheduler] started, checking every 1 minute")
		for {
			select {
			case <-s.ticker.C:
				s.checkAndRun()
			case <-s.stopCh:
				log.Printf("[scheduler] stopped")
				return
			}
		}
	}()
}

// Stop arrête le planificateur (idempotent)
func (s *CronScheduler) Stop() {
	s.stopOnce.Do(func() {
		if s.ticker != nil {
			s.ticker.Stop()
		}
		close(s.stopCh)
	})
}

// GetRunning états des plans en cours d'exécution
func (s *CronScheduler) GetRunning() []PlanRunState {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	out := make([]PlanRunState, 0, len(s.running))
	for _, st := range s.running {
		out = append(out, *st)
	}
	return out
}

func (s *CronScheduler) setRunning(planID int64, st *PlanRunState) {
	s.runMu.Lock()
	if st == nil {
		delete(s.running, planID)
	} else {
		s.running[planID] = st
	}
	s.runMu.Unlock()
}

func (s *CronScheduler) updateRunning(planID int64, fn func(*PlanRunState)) {
	s.runMu.Lock()
	if st, ok := s.running[planID]; ok {
		fn(st)
	}
	s.runMu.Unlock()
}

// checkAndRun vérifie les plans actifs et exécute ceux arrivés à échéance
func (s *CronScheduler) checkAndRun() {
	plans, err := s.db.ListClaimPlans()
	if err != nil {
		log.Printf("[scheduler] list plans: %v", err)
		return
	}
	now := time.Now()
	for _, plan := range plans {
		if !plan.IsActive {
			continue
		}
		if !shouldRun(plan.CronExpr, now) {
			continue
		}
		// Déduplication à la minute : si déjà déclenché dans cette minute, on saute (last_run_at est écrit dès le début d'executePlan)
		if plan.LastRunAt != "" {
			if lastRun, err := time.Parse("2006-01-02 15:04:05", plan.LastRunAt); err == nil {
				if lastRun.Truncate(time.Minute).Equal(now.Truncate(time.Minute)) {
					continue
				}
			}
		}
		go s.executePlan(plan)
	}
}

// RunPlanNow exécution manuelle immédiate (déclenchée par l'UI) ; refusée si déjà en cours
func (s *CronScheduler) RunPlanNow(planID int64) error {
	plan, err := s.db.GetClaimPlan(planID)
	if err != nil {
		return fmt.Errorf("Plan introuvable : %d", planID)
	}
	if !s.planLock(planID).TryLock() {
		return fmt.Errorf("Plan en cours d'exécution, réessayez plus tard")
	}
	s.planLock(planID).Unlock()
	go s.executePlan(plan)
	return nil
}

// executePlan exécute le plan (résolution de l'ensemble des comptes cibles)
func (s *CronScheduler) executePlan(plan *ClaimPlan) {
	lock := s.planLock(plan.ID)
	if !lock.TryLock() {
		return // une exécution est déjà en cours, on saute (pas d'accumulation en file)
	}
	defer lock.Unlock()

	// last_run_at est écrit dès le début pour éviter un déclenchement répété pendant un plan long
	s.db.UpdateClaimPlanRun(plan.ID, "running", "En cours d'exécution")

	targets, err := s.resolveTargets(plan)
	if err != nil {
		s.db.UpdateClaimPlanRun(plan.ID, "failed", err.Error())
		return
	}
	if len(targets) == 0 {
		s.db.UpdateClaimPlanRun(plan.ID, "failed", "Aucun compte correspondant aux critères")
		return
	}

	taskType := plan.TaskType
	if taskType == "" {
		taskType = "claim"
	}
	log.Printf("[scheduler] plan #%d %s (%s) start, %d accounts, delay=%ds",
		plan.ID, plan.PlanName, taskType, len(targets), plan.DelaySeconds)

	start := time.Now()
	s.setRunning(plan.ID, &PlanRunState{
		PlanID: plan.ID, PlanName: plan.PlanName, TaskType: taskType,
		Total: len(targets), StartedAt: start.Format("15:04:05"),
	})
	defer s.setRunning(plan.ID, nil)

	var results []string
	successCount, failCount := 0, 0
	for i, a := range targets {
		if i > 0 && plan.DelaySeconds > 0 {
			// Délai fixe + gigue aléatoire de 0~50 % pour simuler un humain
			jitter := rand.Intn(plan.DelaySeconds/2 + 1)
			sleep := plan.DelaySeconds + jitter
			log.Printf("[scheduler] plan #%d: sleep %ds before %s", plan.ID, sleep, a.DisplayNameOrEmail())
			time.Sleep(time.Duration(sleep) * time.Second)
		}
		s.updateRunning(plan.ID, func(st *PlanRunState) { st.CurrentAccount = a.DisplayNameOrEmail() })

		result := s.executeTask(taskType, a)
		if result.OK {
			successCount++
		} else {
			failCount++
		}
		results = append(results, fmt.Sprintf("%s: %s", a.DisplayNameOrEmail(), result.Message))
		done := i + 1
		s.updateRunning(plan.ID, func(st *PlanRunState) {
			st.Done = done
			st.Success = successCount
			st.Fail = failCount
		})
	}

	status := "success"
	if successCount == 0 {
		status = "failed"
	}
	summary := fmt.Sprintf("%d/%d réussis : %s", successCount, len(targets), strings.Join(results, "; "))
	if len(summary) > 900 {
		summary = summary[:900] + "…"
	}
	duration := int(time.Since(start).Milliseconds())
	s.db.UpdateClaimPlanRun(plan.ID, status, summary)
	s.db.InsertPlanRunRecord(&PlanRunRecord{
		PlanID: plan.ID, PlanName: plan.PlanName, TaskType: taskType,
		TargetType: plan.TargetType, Status: status, Message: summary,
		Total: len(targets), SuccessCount: successCount, FailCount: failCount,
		DurationMs: duration,
	})
	log.Printf("[scheduler] plan #%d done: %s", plan.ID, status)
}

// resolveTargets résout la liste des comptes selon le type de cible du plan
func (s *CronScheduler) resolveTargets(plan *ClaimPlan) ([]*Account, error) {
	switch plan.TargetType {
	case "single_account":
		a, err := s.db.GetAccount(plan.AccountID)
		if err != nil {
			return nil, err
		}
		return []*Account{a}, nil
	case "group":
		if plan.AccountGroup == "" {
			return nil, fmt.Errorf("Cible de groupe sans nom de groupe")
		}
		all, err := s.db.ListAccounts(plan.AccountGroup)
		if err != nil {
			return nil, err
		}
		return filterRunnable(all), nil
	default: // all_accounts
		all, err := s.db.ListAccounts("")
		if err != nil {
			return nil, err
		}
		return filterRunnable(all), nil
	}
}

// filterRunnable filtre les comptes exécutables : activés + non invalid/disabled + avec JWT
func filterRunnable(in []*Account) []*Account {
	var out []*Account
	for _, a := range in {
		if !a.Enabled || a.Status == StatusDisabled || a.Status == StatusInvalid {
			continue
		}
		if a.ZCodeJWT == "" && a.APIKey == "" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// executeTask distribue selon le type de tâche
func (s *CronScheduler) executeTask(taskType string, a *Account) *ClaimResult {
	switch taskType {
	case "detect":
		return s.zapi.DetectForAccount(a)
	case "activate":
		return s.zapi.ActivateForAccount(a)
	case "reset":
		return s.zapi.ResetForAccount(a)
	default: // claim
		return s.zapi.ClaimForAccount(a)
	}
}

// ---- Analyse des expressions cron (5 segments : min heure jour mois semaine) ----

// shouldRun détermine si l'expression cron se déclenche à l'instant donné
func shouldRun(cronExpr string, now time.Time) bool {
	fields := strings.Fields(strings.TrimSpace(cronExpr))
	if len(fields) != 5 {
		return false
	}
	return matchField(fields[0], now.Minute(), 0, 59) &&
		matchField(fields[1], now.Hour(), 0, 23) &&
		matchField(fields[2], now.Day(), 1, 31) &&
		matchField(fields[3], int(now.Month()), 1, 12) &&
		matchField(fields[4], int(now.Weekday()), 0, 6)
}

func matchField(field string, value, min, max int) bool {
	if field == "*" {
		return true
	}
	if strings.HasPrefix(field, "*/") {
		step, err := strconv.Atoi(field[2:])
		if err != nil || step <= 0 {
			return false
		}
		return value%step == 0
	}
	if strings.Contains(field, ",") {
		for _, p := range strings.Split(field, ",") {
			if matchSinglePart(p, value) {
				return true
			}
		}
		return false
	}
	if strings.Contains(field, "/") {
		return matchStep(field, value, min, max)
	}
	if strings.Contains(field, "-") {
		return matchRange(field, value)
	}
	return matchSinglePart(field, value)
}

func matchSinglePart(part string, value int) bool {
	part = strings.TrimSpace(part)
	if part == "*" {
		return true
	}
	n, err := strconv.Atoi(part)
	if err != nil {
		return false
	}
	return n == value
}

func matchRange(field string, value int) bool {
	parts := strings.SplitN(field, "-", 2)
	if len(parts) != 2 {
		return false
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return false
	}
	return value >= start && value <= end
}

func matchStep(field string, value, min, max int) bool {
	parts := strings.SplitN(field, "/", 2)
	if len(parts) != 2 {
		return false
	}
	rangePart := strings.TrimSpace(parts[0])
	step, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || step <= 0 {
		return false
	}
	var start, end int
	if rangePart == "*" {
		start, end = min, max
	} else if strings.Contains(rangePart, "-") {
		rp := strings.SplitN(rangePart, "-", 2)
		start, err = strconv.Atoi(strings.TrimSpace(rp[0]))
		if err != nil {
			return false
		}
		end, err = strconv.Atoi(strings.TrimSpace(rp[1]))
		if err != nil {
			return false
		}
	} else {
		start, err = strconv.Atoi(rangePart)
		if err != nil {
			return false
		}
		end = max
	}
	if value < start || value > end {
		return false
	}
	return (value-start)%step == 0
}

// ValidateCronExpr valide l'expression cron
func ValidateCronExpr(expr string) error {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return fmt.Errorf("L'expression cron doit comporter 5 segments (min heure jour mois semaine), actuellement %d", len(fields))
	}
	ranges := []struct{ min, max int }{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 6}}
	labels := []string{"minute", "heure", "jour", "mois", "semaine"}
	for i, f := range fields {
		if err := validateCronField(f, ranges[i].min, ranges[i].max); err != nil {
			return fmt.Errorf("champ %s : %w", labels[i], err)
		}
	}
	return nil
}

func validateCronField(field string, min, max int) error {
	field = strings.TrimSpace(field)
	if field == "" {
		return fmt.Errorf("Champ vide")
	}
	if field == "*" {
		return nil
	}
	if strings.Contains(field, "/") {
		parts := strings.SplitN(field, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("Format d'incrément invalide")
		}
		step, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || step <= 0 {
			return fmt.Errorf("Valeur d'incrément invalide")
		}
		rangePart := strings.TrimSpace(parts[0])
		if rangePart == "*" {
			return nil
		}
		return validateCronField(rangePart, min, max)
	}
	if strings.Contains(field, ",") {
		for _, p := range strings.Split(field, ",") {
			if err := validateCronField(p, min, max); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.Contains(field, "-") {
		parts := strings.SplitN(field, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("Format de plage invalide")
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return fmt.Errorf("Plage invalide : %s", field)
		}
		if start < min || end > max || start > end {
			return fmt.Errorf("Plage %d-%d hors de [%d-%d]", start, end, min, max)
		}
		return nil
	}
	n, err := strconv.Atoi(field)
	if err != nil {
		return fmt.Errorf("Nombre invalide : %s", field)
	}
	if n < min || n > max {
		return fmt.Errorf("Valeur %d hors de [%d-%d]", n, min, max)
	}
	return nil
}

// NextRunTime calcule la prochaine date de déclenchement (affichage frontend)
func NextRunTime(cronExpr string, from time.Time) time.Time {
	t := from.Truncate(time.Minute).Add(time.Minute)
	limit := t.Add(366 * 24 * time.Hour)
	for t.Before(limit) {
		if shouldRun(cronExpr, t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}
