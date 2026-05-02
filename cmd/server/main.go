package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rohit-Jung/search-engine/config"
	"github.com/rohit-Jung/search-engine/internal/search"
)

func main() {
	var (
		addr           = flag.String("addr", ":8080", "http listen address")
		webDir         = flag.String("web", "./web", "directory to serve static frontend from")
		enableBaseline = flag.Bool("baseline", true, "enable /api/baseline (requires Postgres)")
	)
	flag.Parse()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("load config:", err)
	}

	// build ranked-search engine once at startup (from cached data files by default).
	buildStart := time.Now()
	engine, err := search.Build(search.BuildOptions{Source: "cache", APIKey: cfg.Nvd.APIKey})
	if err != nil {
		log.Fatal("build engine:", err)
	}
	log.Printf("engine ready corpus_n=%v elapsed=%s", engine.Meta()["corpus_n"], time.Since(buildStart).Truncate(time.Second))

	// optional baseline db connection.
	var db *sql.DB
	if *enableBaseline {
		dsn := fmt.Sprintf(
			"postgres://%s:%s@%s:%d/%s",
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.Name,
		)

		db, err = sql.Open("pgx", dsn)

		if err != nil {
			log.Printf("baseline disabled (sql open failed): %v", err)
			db = nil
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := db.PingContext(ctx); err != nil {
				log.Printf("baseline disabled (db ping failed): %v", err)
				_ = db.Close()
				db = nil
			}
		}
	}

	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()

	mux := http.NewServeMux()

	// expose api
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"engine": engine.Meta(),
			"db": map[string]any{
				"enabled": db != nil,
			},
		})
	})

	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		// params: library + severity.
		library := strings.TrimSpace(r.URL.Query().Get("library"))
		if library == "" {
			library = strings.TrimSpace(r.URL.Query().Get("q"))
		}

		severity := strings.TrimSpace(r.URL.Query().Get("severity"))
		if severity == "" {
			severity = "HIGH"
		}

		if library == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing query param library"})
			return
		}

		top := parseIntDefault(r.URL.Query().Get("top"), 10)
		results, meta := engine.Search(search.SearchOptions{Library: library, TopN: top, MinSeverity: severity})
		writeJSON(w, http.StatusOK, map[string]any{
			"meta":    meta,
			"results": results,
		})
	})

	mux.HandleFunc("/api/baseline", func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "baseline DB not enabled"})
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing query param q"})
			return
		}

		top := parseIntDefault(r.URL.Query().Get("top"), 10)
		order := strings.TrimSpace(r.URL.Query().Get("order"))
		field := strings.TrimSpace(r.URL.Query().Get("field"))
		severity := strings.TrimSpace(r.URL.Query().Get("severity"))

		if order == "" {
			order = "published"
		}

		if severity == "" {
			severity = ""
		}

		start := time.Now()
		rows, err := baselineQuery(r.Context(), db, q, top, order, field, severity)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"meta": map[string]any{
				"query":      q,
				"top":        top,
				"order":      order,
				"field":      field,
				"elapsed_ms": time.Since(start).Milliseconds(),
			},
			"results": rows,
		})
	})

	// static frontend (served from the same origin as api).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// try exact file, otherwise serve index.html (SPA-ish behavior).
		// important: url paths are absolute (start with '/'); ensure they don't escape webdir.
		cleanURLPath := pathpkg.Clean("/" + r.URL.Path)

		rel := strings.TrimPrefix(cleanURLPath, "/")
		if strings.HasPrefix(rel, "..") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid path"})
			return
		}

		// default document.
		if rel == "" {
			rel = "index.html"
		}

		onDisk := filepath.Join(*webDir, filepath.FromSlash(rel))
		if info, err := os.Stat(onDisk); err == nil && !info.IsDir() {
			http.ServeFile(w, r, onDisk)
			return
		}

		// fallback to index for unknown paths (so refresh works).
		http.ServeFile(w, r, filepath.Join(*webDir, "index.html"))
	})

	// basic CORS (static frontend is served from same origin anyway, doesn't matter).
	h := withCORS(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on http://localhost%s", normalizeLocalhost(*addr))
	log.Fatal(srv.ListenAndServe())
}

func normalizeLocalhost(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}

	// best-effort; could be 0.0.0.0:8080 etc.
	if strings.Contains(addr, ":") {
		_, port, err := strings.Cut(addr, ":")
		if err {
			return ":8080"
		}
		return ":" + port
	}
	return ":8080"
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}

	return n
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func minCVSSForSeverity(sev string) float64 {
	s := strings.ToUpper(strings.TrimSpace(sev))
	switch s {
	case "LOW":
		return 0.1
	case "MEDIUM":
		return 4.0
	case "HIGH":
		return 7.0
	case "CRITICAL":
		return 9.0
	default:
		return 0
	}
}

type baselineRow struct {
	CVEID       string     `json:"cve_id"`
	Description string     `json:"description"`
	CVSS        *float64   `json:"cvss"`
	Published   *time.Time `json:"published"`
	Vendor      *string    `json:"vendor"`
	Product     *string    `json:"product"`
	Version     *string    `json:"version"`
}

func baselineQuery(
	ctx context.Context,
	db *sql.DB,
	query string,
	top int,
	order string,
	field string,
	severity string,
) ([]baselineRow, error) {
	if top <= 0 {
		top = 10
	}
	if top > 100 {
		top = 100
	}

	orderBy := ""
	switch order {
	case "published":
		orderBy = "ORDER BY published DESC NULLS LAST"
	case "cvss":
		orderBy = "ORDER BY cvss DESC NULLS LAST"
	case "none":
		orderBy = ""
	default:
		orderBy = "ORDER BY published DESC NULLS LAST"
	}

	conds := make([]string, 0, 2)
	args := make([]any, 0, 3)
	args = append(args, query)

	// $1 is always the text query.
	where := "description ILIKE '%%' || $1 || '%%'"
	switch field {
	case "", "description":
		where = "description ILIKE '%%' || $1 || '%%'"
	case "product":
		where = "cpe_product ILIKE '%%' || $1 || '%%'"
	case "all":
		where = "(description ILIKE '%%' || $1 || '%%' OR cpe_product ILIKE '%%' || $1 || '%%' OR cve_id ILIKE '%%' || $1 || '%%')"
	default:
		where = "description ILIKE '%%' || $1 || '%%'"
	}

	conds = append(conds, where)

	min := minCVSSForSeverity(severity)
	if min > 0 {
		// $2 is min CVSS when filtering by severity.
		args = append(args, min)
		conds = append(conds, fmt.Sprintf("cvss >= $%d", len(args)))
	}

	args = append(args, top)
	limitPos := len(args)

	whereSQL := strings.Join(conds, " AND ")
	sqlQuery := fmt.Sprintf(`
SELECT cve_id, description, cvss, published, cpe_vendor, cpe_product, cpe_version
FROM cves
WHERE %s
%s
LIMIT $%d;
`, whereSQL, orderBy, limitPos)

	rows, err := db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []baselineRow
	for rows.Next() {
		var (
			id      string
			desc    string
			cvss    sql.NullFloat64
			pub     sql.NullTime
			vendor  sql.NullString
			product sql.NullString
			version sql.NullString
		)
		if err := rows.Scan(&id, &desc, &cvss, &pub, &vendor, &product, &version); err != nil {
			return nil, err
		}

		var cvssPtr *float64
		if cvss.Valid {
			v := cvss.Float64
			cvssPtr = &v
		}

		var pubPtr *time.Time
		if pub.Valid {
			t := pub.Time
			pubPtr = &t
		}

		var vendorPtr *string
		if vendor.Valid {
			v := vendor.String
			vendorPtr = &v
		}

		var productPtr *string
		if product.Valid {
			v := product.String
			productPtr = &v
		}

		var versionPtr *string
		if version.Valid {
			v := version.String
			versionPtr = &v
		}

		out = append(out, baselineRow{
			CVEID:       id,
			Description: desc,
			CVSS:        cvssPtr,
			Published:   pubPtr,
			Vendor:      vendorPtr,
			Product:     productPtr,
			Version:     versionPtr,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
