package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

// ---- Couche base de données SQLite ----
// Utilise le pilote 100 % Go modernc.org/sqlite, sans CGO (nom d'enregistrement du pilote : "sqlite")

// Account : enregistrement de compte ZCode en base.
// user_id est la clé naturelle : un réimport du même compte fait un upsert sur user_id,
// device_mid / credentials_raw : une fois écrites, ces valeurs ne sont pas effacées par les imports suivants (conservées via COALESCE).
type Account struct {
	ID          int64  `json:"id"`
	UserID      string `json:"user_id"`      // clé naturelle (JWT user_id / user_info.id)
	Email       string `json:"email"`        // e-mail de connexion
	DisplayName string `json:"display_name"` // pseudo
	Provider    string `json:"provider"`     // zai | bigmodel
	AuthType    string `json:"auth_type"`    // jwt | apikey

	AccessToken  string `json:"-"` // OAuth access_token (JWT, contient le claim api_key)
	RefreshToken string `json:"-"` // OAuth refresh_token
	ZCodeJWT     string `json:"-"` // Coding Plan JWT (identifiant du canal gratuit zcode.z.ai)
	APIKey       string `json:"-"` // clé du canal api.z.ai ({api_key}.{secret_key})
	UserInfo     string `json:"-"` // JSON user_info brut
	DeviceMid    string `json:"device_mid"`     // X-Device-Mid (empreinte d'appareil, jamais écrasée par un réimport)
	CredsRaw     string `json:"-"`              // contenu brut du credentials.json du client local (pour la bascule en un clic)

	Status       string `json:"status"`        // active|exhausted|cooling|invalid|disabled|inactive
	Enabled      bool   `json:"enabled"`       // participe ou non à la rotation
	AccountGroup string `json:"group"`         // groupe (vide = non groupé)
	QuotaJSON    string `json:"-"`             // dernier instantané de quota (JSON normalisé)
	PlanTier     string `json:"plan_tier"`     // Start Plan / Lite / Pro / Max / essai
	PlanExpire   string `json:"plan_expire"`   // date d'expiration du forfait (chaîne d'affichage)
	TotalUnits   float64 `json:"total_units"`
	UsedUnits    float64 `json:"used_units"`
	Remaining    float64 `json:"remaining"`

	UseCount      int    `json:"use_count"`
	FailCount     int    `json:"fail_count"`
	LastUsedAt    int64  `json:"last_used_at"`    // secondes epoch
	LastCheckedAt int64  `json:"last_checked_at"` // heure de rafraîchissement du quota, en secondes epoch
	CoolingUntil  int64  `json:"cooling_until"`   // fin du refroidissement, en secondes epoch
	LastError     string `json:"last_error"`

	LastClaimAt   string `json:"last_claim_at"`   // heure du dernier retrait d'activité
	LastClaimPlan string `json:"last_claim_plan"` // nom de la dernière activité retirée
	LastClaimMsg  string `json:"last_claim_msg"`  // résultat du dernier retrait

	Remark    string `json:"remark"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ClaimPlan plan d'activité (ordonnancement cron) : détection / récupération / activation
type ClaimPlan struct {
	ID            int64  `json:"id"`
	PlanName      string `json:"plan_name"`
	CronExpr      string `json:"cron_expr"`      // 5 segments : min heure jour mois semaine
	IsActive      bool   `json:"is_active"`
	TargetType    string `json:"target_type"`    // all_accounts | single_account | group
	AccountID     int64  `json:"account_id"`     // Valide si single_account
	AccountGroup  string `json:"account_group"`  // Valide si group
	TaskType      string `json:"task_type"`      // detect | claim | activate
	AutoPick      bool   `json:"auto_pick"`      // Sélection automatique de la priorité la plus haute lors de claim
	DelaySeconds  int    `json:"delay_seconds"`  // Délai en secondes entre comptes (anti-contrôle)
	LastRunAt     string `json:"last_run_at"`
	LastRunStatus string `json:"last_run_status"`
	LastRunMsg    string `json:"last_run_msg"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ClaimRecord historique de récupération d'activité
type ClaimRecord struct {
	ID         int64  `json:"id"`
	CreatedAt  string `json:"created_at"`
	AccountID  int64  `json:"account_id"`
	Email      string `json:"email"`
	TaskType   string `json:"task_type"` // detect | claim | activate
	PlanID     string `json:"plan_id"`
	PlanName   string `json:"plan_name"`
	Success    bool   `json:"success"`
	Code       int    `json:"code"`
	Message    string `json:"message"`
	NextAt     int64  `json:"next_at"` // Prochaine disponibilité epoch ms lorsque le quota 1005 est épuisé
}

// UsageRecord enregistrement d'utilisation de l'API
type UsageRecord struct {
	ID               int64  `json:"id"`
	CreatedAt        string `json:"created_at"`
	AccountID        int64  `json:"account_id"`
	Email            string `json:"email"`
	Model            string `json:"model"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalTokens      int    `json:"total_tokens"`
	Stream           bool   `json:"stream"`
	StatusCode       int    `json:"status_code"`
	DurationMs       int    `json:"duration_ms"`
	TtftMs           int    `json:"ttft_ms"`
}

// ProxyNode nœud proxy de sortie (lié à un groupe)
type ProxyNode struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"` // socks5 | http
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	IsDefault    bool   `json:"is_default"`
	GroupName    string `json:"group_name"` // Groupes de comptes liés (séparés par virgules)
	Enabled      bool   `json:"enabled"`
	CheckStatus  string `json:"check_status"`
	CheckLatency int    `json:"check_latency"`
	CheckIP      string `json:"check_ip"`
	CheckMsg     string `json:"check_msg"`
	CheckAt      string `json:"check_at"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// PlanRunRecord historique d'exécution de plan
type PlanRunRecord struct {
	ID           int64  `json:"id"`
	PlanID       int64  `json:"plan_id"`
	PlanName     string `json:"plan_name"`
	TaskType     string `json:"task_type"`
	TargetType   string `json:"target_type"`
	AccountID    int64  `json:"account_id"`
	RunAt        string `json:"run_at"`
	Status       string `json:"status"`
	Message      string `json:"message"`
	Total        int    `json:"total"`
	SuccessCount int    `json:"success_count"`
	FailCount    int    `json:"fail_count"`
	DurationMs   int    `json:"duration_ms"`
}

// DB gère la connexion à la base de données
type DB struct {
	conn *sql.DB
}

// NewDB ouvre/crée la base SQLite et initialise le schéma
func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // Écriture unique SQLite
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("exec pragma %q: %w", p, err)
		}
	}
	db := &DB{conn: conn}
	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

// Close ferme la connexion à la base
func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id          TEXT NOT NULL UNIQUE,
		email            TEXT DEFAULT '',
		display_name     TEXT DEFAULT '',
		provider         TEXT DEFAULT 'zai',
		auth_type        TEXT DEFAULT 'jwt',
		access_token     TEXT DEFAULT '',
		refresh_token    TEXT DEFAULT '',
		zcode_jwt        TEXT DEFAULT '',
		api_key          TEXT DEFAULT '',
		user_info        TEXT DEFAULT '',
		device_mid       TEXT DEFAULT '',
		creds_raw        TEXT DEFAULT '',
		status           TEXT DEFAULT 'active',
		enabled          INTEGER DEFAULT 1,
		account_group    TEXT DEFAULT '',
		quota_json       TEXT DEFAULT '',
		plan_tier        TEXT DEFAULT '',
		plan_expire      TEXT DEFAULT '',
		total_units      REAL DEFAULT 0,
		used_units       REAL DEFAULT 0,
		remaining        REAL DEFAULT 0,
		use_count        INTEGER DEFAULT 0,
		fail_count       INTEGER DEFAULT 0,
		last_used_at     INTEGER DEFAULT 0,
		last_checked_at  INTEGER DEFAULT 0,
		cooling_until    INTEGER DEFAULT 0,
		last_error       TEXT DEFAULT '',
		last_claim_at    TEXT DEFAULT '',
		last_claim_plan  TEXT DEFAULT '',
		last_claim_msg   TEXT DEFAULT '',
		remark           TEXT DEFAULT '',
		created_at       TEXT DEFAULT (datetime('now','localtime')),
		updated_at       TEXT DEFAULT (datetime('now','localtime'))
	);
	CREATE INDEX IF NOT EXISTS idx_accounts_enabled ON accounts(enabled);
	CREATE INDEX IF NOT EXISTS idx_accounts_status  ON accounts(status);
	CREATE INDEX IF NOT EXISTS idx_accounts_group   ON accounts(account_group);

	CREATE TABLE IF NOT EXISTS settings (
		key        TEXT PRIMARY KEY,
		value      TEXT DEFAULT '',
		updated_at TEXT DEFAULT (datetime('now','localtime'))
	);

	CREATE TABLE IF NOT EXISTS claim_plans (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		plan_name       TEXT DEFAULT '',
		cron_expr       TEXT NOT NULL DEFAULT '0 9 * * *',
		is_active       INTEGER DEFAULT 1,
		target_type     TEXT DEFAULT 'all_accounts',
		account_id      INTEGER DEFAULT 0,
		account_group   TEXT DEFAULT '',
		task_type       TEXT DEFAULT 'claim',
		auto_pick       INTEGER DEFAULT 1,
		delay_seconds   INTEGER DEFAULT 30,
		last_run_at     TEXT DEFAULT '',
		last_run_status TEXT DEFAULT '',
		last_run_msg    TEXT DEFAULT '',
		created_at      TEXT DEFAULT (datetime('now','localtime')),
		updated_at      TEXT DEFAULT (datetime('now','localtime'))
	);
	CREATE INDEX IF NOT EXISTS idx_claim_plans_active ON claim_plans(is_active);

	CREATE TABLE IF NOT EXISTS claim_records (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at  TEXT DEFAULT (datetime('now','localtime')),
		account_id  INTEGER DEFAULT 0,
		email       TEXT DEFAULT '',
		task_type   TEXT DEFAULT 'claim',
		plan_id     TEXT DEFAULT '',
		plan_name   TEXT DEFAULT '',
		success     INTEGER DEFAULT 0,
		code        INTEGER DEFAULT 0,
		message     TEXT DEFAULT '',
		next_at     INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_claim_records_account ON claim_records(account_id);
	CREATE INDEX IF NOT EXISTS idx_claim_records_created ON claim_records(created_at);

	CREATE TABLE IF NOT EXISTS usage_records (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at        TEXT DEFAULT (datetime('now','localtime')),
		account_id        INTEGER DEFAULT 0,
		email             TEXT DEFAULT '',
		model             TEXT DEFAULT '',
		prompt_tokens     INTEGER DEFAULT 0,
		completion_tokens INTEGER DEFAULT 0,
		total_tokens      INTEGER DEFAULT 0,
		stream            INTEGER DEFAULT 0,
		status_code       INTEGER DEFAULT 0,
		duration_ms       INTEGER DEFAULT 0,
		ttft_ms           INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_usage_records_created ON usage_records(created_at);
	CREATE INDEX IF NOT EXISTS idx_usage_records_account ON usage_records(account_id);
	CREATE INDEX IF NOT EXISTS idx_usage_records_model   ON usage_records(model);

	CREATE TABLE IF NOT EXISTS proxy_nodes (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		name          TEXT DEFAULT '',
		type          TEXT DEFAULT 'socks5',
		host          TEXT DEFAULT '',
		port          INTEGER DEFAULT 0,
		username      TEXT DEFAULT '',
		password      TEXT DEFAULT '',
		is_default    INTEGER DEFAULT 0,
		group_name    TEXT DEFAULT '',
		enabled       INTEGER DEFAULT 1,
		check_status  TEXT DEFAULT '',
		check_latency INTEGER DEFAULT 0,
		check_ip      TEXT DEFAULT '',
		check_msg     TEXT DEFAULT '',
		check_at      TEXT DEFAULT '',
		created_at    TEXT DEFAULT (datetime('now','localtime')),
		updated_at    TEXT DEFAULT (datetime('now','localtime'))
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_nodes_default ON proxy_nodes(is_default) WHERE is_default = 1;

	CREATE TABLE IF NOT EXISTS plan_run_records (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		plan_id       INTEGER DEFAULT 0,
		plan_name     TEXT DEFAULT '',
		task_type     TEXT DEFAULT '',
		target_type   TEXT DEFAULT '',
		account_id    INTEGER DEFAULT 0,
		run_at        TEXT DEFAULT (datetime('now','localtime')),
		status        TEXT DEFAULT '',
		message       TEXT DEFAULT '',
		total         INTEGER DEFAULT 0,
		success_count INTEGER DEFAULT 0,
		fail_count    INTEGER DEFAULT 0,
		duration_ms   INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_plan_run_records_run_at ON plan_run_records(run_at);
	CREATE INDEX IF NOT EXISTS idx_plan_run_records_plan   ON plan_run_records(plan_id);
	`
	if _, err := db.conn.Exec(schema); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	// Paramètres par défaut
	defaults := map[string]string{
		"admin_user":             "admin",
		"is_default_password":    "1",
		"api_key":                "",
		"selection_strategy":     "round_robin",
		"quota_refresh_interval": "60",
		"app_version":            "",
		"upstream_proxy":         "",
		"fingerprint":            "chrome",
		"custom_ja3":             "",
		"captcha_mode":           "auto",
		"gateway_models":         "",
	}
	for k, v := range defaults {
		if _, err := db.conn.Exec(
			`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, k, v); err != nil {
			log.Printf("[db] seed setting %s: %v", k, err)
		}
	}
	return nil
}
