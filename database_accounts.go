package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ---- CRUD des comptes ----

// UpsertAccount insère ou met à jour un compte selon la clé naturelle user_id.
// device_mid / creds_raw utilisent COALESCE(NULLIF(excluded.x,''), accounts.x) :
// conserve l'ancienne valeur si la nouvelle est vide pour préserver l'empreinte et le snapshot.
func (db *DB) UpsertAccount(a *Account) (int64, error) {
	res, err := db.conn.Exec(`
		INSERT INTO accounts (
			user_id, email, display_name, provider, auth_type,
			access_token, refresh_token, zcode_jwt, api_key, user_info,
			device_mid, creds_raw, status, enabled, account_group, remark
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET
			email         = COALESCE(NULLIF(excluded.email,''), accounts.email),
			display_name  = COALESCE(NULLIF(excluded.display_name,''), accounts.display_name),
			provider      = excluded.provider,
			auth_type     = excluded.auth_type,
			access_token  = COALESCE(NULLIF(excluded.access_token,''), accounts.access_token),
			refresh_token = COALESCE(NULLIF(excluded.refresh_token,''), accounts.refresh_token),
			zcode_jwt     = COALESCE(NULLIF(excluded.zcode_jwt,''), accounts.zcode_jwt),
			api_key       = COALESCE(NULLIF(excluded.api_key,''), accounts.api_key),
			user_info     = COALESCE(NULLIF(excluded.user_info,''), accounts.user_info),
			device_mid    = COALESCE(NULLIF(excluded.device_mid,''), accounts.device_mid),
			creds_raw     = COALESCE(NULLIF(excluded.creds_raw,''), accounts.creds_raw),
			status        = CASE WHEN accounts.status IN ('disabled') THEN accounts.status ELSE excluded.status END,
			enabled       = excluded.enabled,
			account_group = COALESCE(NULLIF(excluded.account_group,''), accounts.account_group),
			remark        = COALESCE(NULLIF(excluded.remark,''), accounts.remark),
			updated_at    = datetime('now','localtime')`,
		a.UserID, a.Email, a.DisplayName, a.Provider, a.AuthType,
		a.AccessToken, a.RefreshToken, a.ZCodeJWT, a.APIKey, a.UserInfo,
		a.DeviceMid, a.CredsRaw, a.Status, boolInt(a.Enabled), a.AccountGroup, a.Remark)
	if err != nil {
		return 0, err
	}
	// Récupérer l'ID réel (LastInsertId à l'insertion, ou requête par user_id en cas de conflit)
	id, err := res.LastInsertId()
	if err != nil || id == 0 {
		row := db.conn.QueryRow(`SELECT id FROM accounts WHERE user_id = ?`, a.UserID)
		if err := row.Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const accountCols = `id, user_id, email, display_name, provider, auth_type,
	access_token, refresh_token, zcode_jwt, api_key, user_info, device_mid, creds_raw,
	status, enabled, account_group, quota_json, plan_tier, plan_expire,
	total_units, used_units, remaining, use_count, fail_count,
	last_used_at, last_checked_at, cooling_until, last_error,
	last_claim_at, last_claim_plan, last_claim_msg, remark, created_at, updated_at`

func scanAccount(row interface{ Scan(...interface{}) error }) (*Account, error) {
	var a Account
	var enabled int
	err := row.Scan(
		&a.ID, &a.UserID, &a.Email, &a.DisplayName, &a.Provider, &a.AuthType,
		&a.AccessToken, &a.RefreshToken, &a.ZCodeJWT, &a.APIKey, &a.UserInfo, &a.DeviceMid, &a.CredsRaw,
		&a.Status, &enabled, &a.AccountGroup, &a.QuotaJSON, &a.PlanTier, &a.PlanExpire,
		&a.TotalUnits, &a.UsedUnits, &a.Remaining, &a.UseCount, &a.FailCount,
		&a.LastUsedAt, &a.LastCheckedAt, &a.CoolingUntil, &a.LastError,
		&a.LastClaimAt, &a.LastClaimPlan, &a.LastClaimMsg, &a.Remark, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled == 1
	return &a, nil
}

// GetAccount recherche par ID
func (db *DB) GetAccount(id int64) (*Account, error) {
	row := db.conn.QueryRow(`SELECT `+accountCols+` FROM accounts WHERE id = ?`, id)
	a, err := scanAccount(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("Compte introuvable : %d", id)
	}
	return a, err
}

// GetAccountByUserID recherche par clé naturelle
func (db *DB) GetAccountByUserID(userID string) (*Account, error) {
	row := db.conn.QueryRow(`SELECT `+accountCols+` FROM accounts WHERE user_id = ?`, userID)
	a, err := scanAccount(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListAccounts liste les comptes ; filtre par groupe si non vide
func (db *DB) ListAccounts(group string) ([]*Account, error) {
	query := `SELECT ` + accountCols + ` FROM accounts`
	var args []interface{}
	if group != "" {
		query += ` WHERE account_group = ?`
		args = append(args, group)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAccount supprime un compte
func (db *DB) DeleteAccount(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// UpdateAccountFields met à jour les champs modifiables (groupe, note, activation)
func (db *DB) UpdateAccountFields(id int64, group, remark string, enabled bool) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET account_group = ?, remark = ?, enabled = ?,
		status = CASE WHEN ? = 0 AND status != 'disabled' THEN 'disabled'
		             WHEN ? = 1 AND status = 'disabled' THEN 'active'
		             ELSE status END,
		updated_at = datetime('now','localtime') WHERE id = ?`,
		group, remark, boolInt(enabled), boolInt(enabled), boolInt(enabled), id)
	return err
}

// UpdateAccountTokens met à jour les identifiants
func (db *DB) UpdateAccountTokens(id int64, accessToken, refreshToken, zcodeJWT, apiKey, userInfo string) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET
			access_token  = COALESCE(NULLIF(?,''), access_token),
			refresh_token = COALESCE(NULLIF(?,''), refresh_token),
			zcode_jwt     = COALESCE(NULLIF(?,''), zcode_jwt),
			api_key       = COALESCE(NULLIF(?,''), api_key),
			user_info     = COALESCE(NULLIF(?,''), user_info),
			updated_at = datetime('now','localtime')
		WHERE id = ?`, accessToken, refreshToken, zcodeJWT, apiKey, userInfo, id)
	return err
}

// SetAccountStatus définit le statut du compte et le refroidissement
func (db *DB) SetAccountStatus(id int64, status, lastError string, coolingUntil int64) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET status = ?, last_error = ?, cooling_until = ?,
		updated_at = datetime('now','localtime') WHERE id = ?`,
		status, lastError, coolingUntil, id)
	return err
}

// SetAccountQuota enregistre l'instantané de quota
func (db *DB) SetAccountQuota(id int64, quotaJSON, planTier, planExpire string, total, used, remaining float64) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET quota_json = ?, plan_tier = ?, plan_expire = ?,
		total_units = ?, used_units = ?, remaining = ?,
		last_checked_at = ?, updated_at = datetime('now','localtime') WHERE id = ?`,
		quotaJSON, planTier, planExpire, total, used, remaining, time.Now().Unix(), id)
	return err
}

// TouchAccountUse enregistre une utilisation avec succès
func (db *DB) TouchAccountUse(id int64) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET use_count = use_count + 1, last_used_at = ?,
		status = CASE WHEN status IN ('cooling','exhausted') THEN 'active' ELSE status END,
		cooling_until = 0,
		updated_at = datetime('now','localtime') WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// BumpAccountFail enregistre un échec
func (db *DB) BumpAccountFail(id int64, lastError string) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET fail_count = fail_count + 1, last_error = ?,
		updated_at = datetime('now','localtime') WHERE id = ?`, lastError, id)
	return err
}

// SetAccountClaimResult enregistre le résultat d'une récupération
func (db *DB) SetAccountClaimResult(id int64, planName, msg string) error {
	_, err := db.conn.Exec(`
		UPDATE accounts SET last_claim_at = datetime('now','localtime'),
		last_claim_plan = ?, last_claim_msg = ?,
		updated_at = datetime('now','localtime') WHERE id = ?`, planName, msg, id)
	return err
}

// ListGroups renvoie la liste de tous les groupes utilisés
func (db *DB) ListGroups() ([]string, error) {
	rows, err := db.conn.Query(`
		SELECT account_group FROM accounts WHERE account_group != ''
		UNION
		SELECT group_name FROM proxy_nodes WHERE group_name != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			continue
		}
		// group_name peut être une liste séparée par des virgules
		for _, part := range strings.Split(g, ",") {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	return out, rows.Err()
}

// CountAccountsByStatus statistiques de statuts pour le tableau de bord
func (db *DB) CountAccountsByStatus() (map[string]int, error) {
	rows, err := db.conn.Query(`SELECT status, COUNT(*) FROM accounts GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err == nil {
			out[s] = n
		}
	}
	return out, rows.Err()
}
