package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rohit-Jung/search-engine/config"
	"github.com/rohit-Jung/search-engine/internal/parser"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("load config:", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("db ping:", err)
	}

	if err := ensureSchema(ctx, db); err != nil {
		log.Fatal("schema:", err)
	}

	files, err := filepath.Glob("./data/data-*.json")
	if err != nil {
		log.Fatal(err)
	}

	if len(files) == 0 {
		log.Fatal("no cached NVD pages found under ./data (expected data-*.json)")
	}

	sort.Strings(files)

	start := time.Now()
	var inserted int

	for i, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("skip read %s: %v", path, err)
			continue
		}

		var page parser.NVDResponse
		if err := json.Unmarshal(b, &page); err != nil {
			log.Printf("skip json %s: %v", path, err)
			continue
		}

		n, err := loadPage(ctx, db, page.Vulnerabilities)
		if err != nil {
			log.Fatal("load page:", err)
		}
		inserted += n

		if (i+1)%10 == 0 {
			log.Printf("loaded pages=%d/%d rows=%d elapsed=%s", i+1, len(files), inserted, time.Since(start).Truncate(time.Second))
		}
	}

	log.Printf("done. inserted=%d elapsed=%s", inserted, time.Since(start).Truncate(time.Second))
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	// minimal relational projection for baseline select queries.
	// raw json is retained for traceability and to support future experiments.
	ddl := `
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  published TIMESTAMPTZ NULL,
  cvss REAL NULL,
  cpe_part TEXT NULL,
  cpe_vendor TEXT NULL,
  cpe_product TEXT NULL,
  cpe_version TEXT NULL,
  vuln_status TEXT NULL,
  raw JSONB NOT NULL
);

-- If the table already exists from a prior run, ensure new columns exist.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cpe_part TEXT NULL;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cpe_vendor TEXT NULL;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cpe_product TEXT NULL;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cpe_version TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_cves_description_trgm ON cves USING gin (description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves (cvss);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves (published);
CREATE INDEX IF NOT EXISTS idx_cves_cpe_product ON cves (cpe_product);
CREATE INDEX IF NOT EXISTS idx_cves_cpe_product_trgm ON cves USING gin (cpe_product gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_cpe_vendor_trgm ON cves USING gin (cpe_vendor gin_trgm_ops);
`

	// pg_trgm for fast ILIKE baseline.
	if _, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pg_trgm;`); err != nil {
		return err
	}

	_, err := db.ExecContext(ctx, ddl)
	return err
}

func loadPage(ctx context.Context, db *sql.DB, vulnerabilities []parser.Vulnerability) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO cves (cve_id, description, published, cvss, cpe_part, cpe_vendor, cpe_product, cpe_version, vuln_status, raw)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (cve_id) DO UPDATE
SET description = EXCLUDED.description,
    published = EXCLUDED.published,
    cvss = EXCLUDED.cvss,
    cpe_part = EXCLUDED.cpe_part,
    cpe_vendor = EXCLUDED.cpe_vendor,
    cpe_product = EXCLUDED.cpe_product,
    cpe_version = EXCLUDED.cpe_version,
    vuln_status = EXCLUDED.vuln_status,
    raw = EXCLUDED.raw;
`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var n int
	for _, v := range vulnerabilities {
		c := v.CVE
		if c.ID == "" {
			continue
		}

		desc := ""
		if len(c.Descriptions) > 0 {
			desc = c.Descriptions[0].Value
		}
		if desc == "" {
			continue
		}

		cvss := c.GetCVSSScore()
		var cvssPtr any
		if cvss == 0 {
			cvssPtr = nil
		} else {
			cvssPtr = float32(cvss)
		}

		part, vendor, product, version := firstCPEDetails(c)

		pub := time.Time(c.Published.Time)
		var pubPtr any
		if pub.IsZero() {
			pubPtr = nil
		} else {
			pubPtr = pub
		}

		raw, err := json.Marshal(c)
		if err != nil {
			return n, err
		}

		_, err = stmt.ExecContext(ctx,
			c.ID,
			desc,
			pubPtr,
			cvssPtr,
			nullIfEmpty(part),
			nullIfEmpty(vendor),
			nullIfEmpty(product),
			nullIfEmpty(version),
			strings.ToLower(c.VulnStatus),
			raw,
		)
		if err != nil {
			return n, err
		}
		n++
	}

	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func firstCPEDetails(c parser.CVE) (part, vendor, product, version string) {
	for _, conf := range c.Configurations {
		for _, node := range conf.Nodes {
			for _, cpe := range node.CPEMatch {
				parts := strings.Split(cpe.Criteria, ":")
				// expect: cpe:2.3:<part>:<vendor>:<product>:<version>:...
				if len(parts) < 6 {
					continue
				}
				p := parts[4]
				if p == "" {
					continue
				}
				return parts[2], parts[3], parts[4], parts[5]
			}
		}
	}
	return "", "", "", ""
}
