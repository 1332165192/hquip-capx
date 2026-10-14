package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hquip/capx/internal/model"
	_ "modernc.org/sqlite"
)

// HTTPQuery controls paged HTTP-history reads from the disk index.
type HTTPQuery struct {
	Filter HTTPFilter
	Limit  int
	Offset int
	// Summary omits raw bodies from rows; they remain searchable in SQLite.
	Summary bool
}

// HTTPDisk stores HTTP transaction metadata and raw messages in SQLite. It is
// intentionally append/query oriented: list views read summaries by page, while
// detail views fetch raw request/response by id.
type HTTPDisk struct {
	db *sql.DB
}

func OpenHTTPDisk(path string) (*HTTPDisk, error) {
	if path == "" {
		return nil, errors.New("empty http disk path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA temp_store=MEMORY`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS history_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS http_txs (
			id INTEGER PRIMARY KEY,
			flow_id TEXT,
			ts TEXT NOT NULL,
			last_seen TEXT,
			scheme TEXT,
			method TEXT,
			host TEXT,
			path TEXT,
			url TEXT,
			status INTEGER,
			resp_len INTEGER,
			proto TEXT,
			mime TEXT,
			req_hdr TEXT,
			resp_hdr TEXT,
			req_raw TEXT,
			resp_raw TEXT,
				decrypted INTEGER,
				repeat_count INTEGER,
				server_addr TEXT,
				in_scope INTEGER DEFAULT 1,
				body_truncated INTEGER DEFAULT 0
			)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_seen ON http_txs(last_seen DESC, ts DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_host ON http_txs(host)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_method ON http_txs(method)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_status ON http_txs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_scheme ON http_txs(scheme)`,
		`CREATE INDEX IF NOT EXISTS idx_http_txs_mime ON http_txs(mime)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, err
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE http_txs ADD COLUMN in_scope INTEGER DEFAULT 1`,
		`ALTER TABLE http_txs ADD COLUMN body_truncated INTEGER DEFAULT 0`,
		`ALTER TABLE http_txs ADD COLUMN capture_mode TEXT DEFAULT ''`,
		`ALTER TABLE http_txs ADD COLUMN client_addr TEXT DEFAULT ''`,
		`ALTER TABLE http_txs ADD COLUMN capture_peer TEXT DEFAULT ''`,
	} {
		_, _ = db.Exec(stmt)
	}
	if err := normalizeHistoryTimes(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("normalize history timestamps: %w", err)
	}
	return &HTTPDisk{db: db}, nil
}

// RFC3339Nano drops zero fractional digits: lexical "...03Z" sorts after
// "...03.1Z". Normalize old UTC rows once, and always write fixed-width times.
func normalizeHistoryTimes(db *sql.DB) error {
	var done int
	err := db.QueryRow(`SELECT value FROM history_meta WHERE key='fixed_time_format'`).Scan(&done)
	if err == nil && done == 1 {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	normalize := func(column string) string {
		return `CASE WHEN ` + column + ` IS NULL OR ` + column + ` = '' THEN ` + column + ` WHEN instr(` + column + `, '.') > 0 THEN substr(` + column + `,1,19) || '.' || substr(rtrim(substr(` + column + `,21),'Z') || '000000000',1,9) || 'Z' ELSE substr(` + column + `,1,19) || '.000000000Z' END`
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE http_txs SET ts=` + normalize("ts") + `, last_seen=` + normalize("last_seen")); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO history_meta(key,value) VALUES('fixed_time_format',1)`); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *HTTPDisk) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

func (d *HTTPDisk) MaxID() uint64 {
	if d == nil || d.db == nil {
		return 0
	}
	var id uint64
	_ = d.db.QueryRow(`SELECT MAX(COALESCE((SELECT MAX(id) FROM http_txs), 0), COALESCE((SELECT value FROM history_meta WHERE key='http_highwater'), 0))`).Scan(&id)
	return id
}

func (d *HTTPDisk) Generation() uint64 {
	var generation uint64
	_ = d.db.QueryRow(`SELECT value FROM history_meta WHERE key='generation'`).Scan(&generation)
	return generation
}

func (d *HTTPDisk) highwater(key string) uint64 {
	var value uint64
	_ = d.db.QueryRow(`SELECT value FROM history_meta WHERE key=?`, key).Scan(&value)
	return value
}

// Clear commits deletion and its durable generation in the same transaction.
// The generation prevents a stale JSON snapshot resurrecting cleared traffic.
func (d *HTTPDisk) Clear(highwater, wsHighwater, eventHighwater, generation uint64) (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM http_txs`).Scan(&count); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`INSERT INTO history_meta(key,value) VALUES('http_highwater',?) ON CONFLICT(key) DO UPDATE SET value=MAX(value,excluded.value)`, highwater); err != nil {
		return 0, err
	}
	for key, value := range map[string]uint64{"ws_highwater": wsHighwater, "event_highwater": eventHighwater} {
		if _, err = tx.Exec(`INSERT INTO history_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=MAX(value,excluded.value)`, key, value); err != nil {
			return 0, err
		}
	}
	if _, err = tx.Exec(`INSERT INTO history_meta(key,value) VALUES('generation',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, generation); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`DELETE FROM http_txs`); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (d *HTTPDisk) Upsert(tx *model.HTTPTx) error {
	if d == nil || d.db == nil || tx == nil {
		return nil
	}
	reqHdr, _ := json.Marshal(tx.ReqHdr)
	respHdr, _ := json.Marshal(tx.RespHdr)
	_, err := d.db.Exec(`
	INSERT INTO http_txs (
		id, flow_id, ts, last_seen, scheme, method, host, path, url, status,
		resp_len, proto, mime, req_hdr, resp_hdr, req_raw, resp_raw, decrypted,
		repeat_count, server_addr, in_scope, body_truncated, capture_mode, client_addr, capture_peer
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		flow_id=excluded.flow_id,
		ts=excluded.ts,
		last_seen=excluded.last_seen,
		scheme=excluded.scheme,
		method=excluded.method,
		host=excluded.host,
		path=excluded.path,
		url=excluded.url,
		status=excluded.status,
		resp_len=excluded.resp_len,
		proto=excluded.proto,
		mime=excluded.mime,
		req_hdr=excluded.req_hdr,
		resp_hdr=excluded.resp_hdr,
		req_raw=excluded.req_raw,
		resp_raw=excluded.resp_raw,
		decrypted=excluded.decrypted,
		repeat_count=excluded.repeat_count,
		server_addr=excluded.server_addr,
		in_scope=excluded.in_scope,
		body_truncated=excluded.body_truncated,
		capture_mode=excluded.capture_mode,
		client_addr=excluded.client_addr,
		capture_peer=excluded.capture_peer`,
		tx.ID, tx.FlowID, timeText(tx.TS), timeText(tx.LastSeen), tx.Scheme, tx.Method,
		tx.Host, tx.Path, tx.URL, tx.Status, tx.RespLen, tx.Proto, tx.MIME,
		string(reqHdr), string(respHdr), tx.ReqRaw, tx.RespRaw, boolInt(tx.Decrypted),
		tx.RepeatCnt, tx.ServerAddr, boolInt(!tx.OutOfScope), boolInt(tx.BodyTruncated), tx.CaptureMode, tx.ClientAddr, tx.CapturePeer)
	return err
}

func (d *HTTPDisk) Get(id uint64) (*model.HTTPTx, error) {
	if d == nil || d.db == nil {
		return nil, sql.ErrNoRows
	}
	rows, err := d.queryRows(d.db, `WHERE id = ?`, "", []any{id}, 1, 0, false)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanHTTPRow(rows)
}

func (d *HTTPDisk) Query(q HTTPQuery) ([]*model.HTTPTx, error) {
	if d == nil || d.db == nil {
		return nil, nil
	}
	where, args := httpWhere(q.Filter)
	rows, err := d.queryRows(d.db, where, orderHTTP(), args, q.Limit, q.Offset, q.Summary)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.HTTPTx
	for rows.Next() {
		tx, err := scanHTTPRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	return out, rows.Err()
}

type httpQuerier interface {
	Query(string, ...any) (*sql.Rows, error)
}

// QueryPage returns count and page from the same SQLite read transaction.
func (d *HTTPDisk) QueryPage(q HTTPQuery) ([]*model.HTTPTx, int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	where, args := httpWhere(q.Filter)
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM http_txs `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.queryRows(tx, where, orderHTTP(), args, q.Limit, q.Offset, q.Summary)
	if err != nil {
		return nil, 0, err
	}
	var out []*model.HTTPTx
	for rows.Next() {
		item, scanErr := scanHTTPRow(rows)
		if scanErr != nil {
			rows.Close()
			return nil, 0, scanErr
		}
		out = append(out, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return out, total, tx.Commit()
}

func (d *HTTPDisk) queryRows(db httpQuerier, where, order string, args []any, limit, offset int, summary bool) (*sql.Rows, error) {
	if order == "" {
		order = orderHTTP()
	}
	bodyColumns := "req_raw, resp_raw"
	if summary {
		bodyColumns = "'', ''"
	}
	query := `SELECT id, flow_id, ts, last_seen, scheme, method, host, path, url,
	status, resp_len, proto, mime, req_hdr, resp_hdr, ` + bodyColumns + `, decrypted,
	repeat_count, server_addr, in_scope, body_truncated,
	COALESCE(capture_mode,''),COALESCE(client_addr,''),COALESCE(capture_peer,''),
	COALESCE(length(CAST(req_raw AS BLOB)),0), COALESCE(length(CAST(resp_raw AS BLOB)),0) FROM http_txs ` + where + " " + order
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		if limit <= 0 {
			query += " LIMIT -1"
		}
		query += " OFFSET ?"
		args = append(args, offset)
	}
	return db.Query(query, args...)
}

func orderHTTP() string {
	return `ORDER BY COALESCE(NULLIF(last_seen, ''), ts) DESC, id DESC`
}

func httpWhere(f HTTPFilter) (string, []any) {
	var clauses []string
	var args []any
	if f.Scheme != "" {
		clauses = append(clauses, "LOWER(scheme) = ?")
		args = append(args, strings.ToLower(f.Scheme))
	}
	if f.Host != "" {
		clauses = append(clauses, "INSTR(LOWER(host), ?) > 0")
		args = append(args, strings.ToLower(f.Host))
	}
	if methods := splitCSVLower(f.Method); len(methods) > 0 {
		var qs []string
		for m := range methods {
			qs = append(qs, "?")
			args = append(args, strings.ToUpper(m))
		}
		clauses = append(clauses, "UPPER(method) IN ("+strings.Join(qs, ",")+")")
	}
	if f.MIME != "" {
		clauses = append(clauses, "INSTR(LOWER(mime), ?) > 0")
		args = append(args, strings.ToLower(f.MIME))
	}
	if c, ok := statusSQL(f.Status, &args); ok {
		clauses = append(clauses, c)
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		clauses = append(clauses, `(INSTR(LOWER(url), ?) > 0 OR INSTR(LOWER(host), ?) > 0 OR INSTR(LOWER(path), ?) > 0 OR INSTR(LOWER(method), ?) > 0 OR INSTR(LOWER(mime), ?) > 0 OR INSTR(CAST(status AS TEXT), ?) > 0 OR INSTR(LOWER(req_raw), ?) > 0 OR INSTR(LOWER(resp_raw), ?) > 0)`)
		args = append(args, q, q, q, q, q, q, q, q)
	}
	switch strings.ToLower(strings.TrimSpace(f.Scope)) {
	case "in":
		clauses = append(clauses, "in_scope != 0")
	case "out":
		clauses = append(clauses, "in_scope = 0")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func statusSQL(spec string, args *[]any) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 == nil && err2 == nil {
			*args = append(*args, l, h)
			return "status BETWEEN ? AND ?", true
		}
		return "1 = 0", true
	}
	if len(spec) == 3 && (spec[1] == 'x' || spec[1] == 'X') && (spec[2] == 'x' || spec[2] == 'X') {
		d := int(spec[0] - '0')
		if d >= 1 && d <= 9 {
			*args = append(*args, d*100, (d+1)*100)
			return "status >= ? AND status < ?", true
		}
		return "1 = 0", true
	}
	n, err := strconv.Atoi(spec)
	if err != nil {
		return "1 = 0", true
	}
	*args = append(*args, n)
	return "status = ?", true
}

func scanHTTPRow(rows interface {
	Scan(dest ...any) error
}) (*model.HTTPTx, error) {
	var tx model.HTTPTx
	var ts, lastSeen, reqHdr, respHdr string
	var decrypted, inScope, truncated int
	err := rows.Scan(&tx.ID, &tx.FlowID, &ts, &lastSeen, &tx.Scheme, &tx.Method,
		&tx.Host, &tx.Path, &tx.URL, &tx.Status, &tx.RespLen, &tx.Proto, &tx.MIME,
		&reqHdr, &respHdr, &tx.ReqRaw, &tx.RespRaw, &decrypted, &tx.RepeatCnt,
		&tx.ServerAddr, &inScope, &truncated, &tx.CaptureMode, &tx.ClientAddr, &tx.CapturePeer, &tx.ReqRawLen, &tx.RespRawLen)
	if err != nil {
		return nil, err
	}
	tx.TS = parseTime(ts)
	tx.LastSeen = parseTime(lastSeen)
	tx.Decrypted = decrypted != 0
	tx.InScope = inScope != 0
	tx.OutOfScope = inScope == 0
	tx.BodyTruncated = truncated != 0
	_ = json.Unmarshal([]byte(reqHdr), &tx.ReqHdr)
	_ = json.Unmarshal([]byte(respHdr), &tx.RespHdr)
	return &tx, nil
}

func timeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// EnableHTTPDisk turns on disk-backed HTTP history. New transactions are
// written to SQLite and list/detail reads can use the disk index.
func (s *Store) EnableHTTPDisk(path string) error {
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	d, err := OpenHTTPDisk(path)
	if err != nil {
		return fmt.Errorf("http disk: %w", err)
	}
	if maxID := d.MaxID(); maxID > s.txSeq.Load() {
		s.txSeq.Store(maxID)
	}
	advanceCounter(&s.wsSeq, d.highwater("ws_highwater"))
	advanceCounter(&s.seq, d.highwater("event_highwater"))
	s.mu.Lock()
	if generation := d.Generation(); generation > s.historyGeneration {
		s.clearTrafficLocked()
		s.historyGeneration = generation
	}
	s.httpDisk = d
	s.mu.Unlock()
	return nil
}

func (s *Store) CloseHTTPDisk() error {
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	s.mu.Lock()
	d := s.httpDisk
	s.httpDisk = nil
	s.mu.Unlock()
	return d.Close()
}

func (s *Store) httpDiskSnapshot() *HTTPDisk {
	s.mu.RLock()
	d := s.httpDisk
	s.mu.RUnlock()
	return d
}

func (s *Store) QueryHTTPTx(q HTTPQuery) ([]*model.HTTPTx, bool, error) {
	s.historyMu.RLock()
	defer s.historyMu.RUnlock()
	s.mu.RLock()
	d := s.httpDisk
	s.mu.RUnlock()
	if d == nil {
		return nil, false, nil
	}
	out, err := d.Query(q)
	return out, true, err
}

func (s *Store) QueryHTTPPage(q HTTPQuery) ([]*model.HTTPTx, int, bool, error) {
	s.historyMu.RLock()
	defer s.historyMu.RUnlock()
	s.mu.RLock()
	d := s.httpDisk
	s.mu.RUnlock()
	if d == nil {
		return nil, 0, false, nil
	}
	out, total, err := d.QueryPage(q)
	return out, total, true, err
}
