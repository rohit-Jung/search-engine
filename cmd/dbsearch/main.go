package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rohit-Jung/search-engine/config"
)

type row struct {
	CVEID       string
	Description string
	CVSS        sql.NullFloat64
	Published   sql.NullTime
	Vendor      sql.NullString
	Product     sql.NullString
	Version     sql.NullString
}

func main() {
	var (
		query = flag.String("query", "openssl", "query string")
		topN  = flag.Int("top", 5, "number of results")
		order = flag.String("order", "published", "order: published|cvss|none")
		field = flag.String("field", "description", "field: description|product|all")
	)
	flag.Parse()

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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("db ping:", err)
	}

	orderBy := ""
	switch *order {
	case "published":
		orderBy = "ORDER BY published DESC NULLS LAST"
	case "cvss":
		orderBy = "ORDER BY cvss DESC NULLS LAST"
	case "none":
		orderBy = ""
	default:
		log.Fatalf("unknown order=%q (expected published|cvss|none)", *order)
	}

	// baseline: plain substring match (no ranking).
	// using parameterized query avoids injection.
	where := "description ILIKE '%%' || $1 || '%%'"
	switch *field {
	case "description":
		where = "description ILIKE '%%' || $1 || '%%'"
	case "product":
		where = "cpe_product ILIKE '%%' || $1 || '%%'"
	case "all":
		where = "(description ILIKE '%%' || $1 || '%%' OR cpe_product ILIKE '%%' || $1 || '%%' OR cve_id ILIKE '%%' || $1 || '%%')"
	default:
		log.Fatalf("unknown field=%q (expected description|product|all)", *field)
	}

	sqlQuery := fmt.Sprintf(`
SELECT cve_id, description, cvss, published, cpe_vendor, cpe_product, cpe_version
FROM cves
WHERE %s
%s
LIMIT $2;
`, where, orderBy)

	start := time.Now()
	rows, err := db.QueryContext(ctx, sqlQuery, *query, *topN)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.CVEID, &r.Description, &r.CVSS, &r.Published, &r.Vendor, &r.Product, &r.Version); err != nil {
			log.Fatal(err)
		}

		out = append(out, r)
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	elapsed := time.Since(start)
	log.Printf("db baseline query=%q field=%s order=%s results=%d elapsed=%s", *query, *field, *order, len(out), elapsed)

	for i, r := range out {
		cvss := 0.0
		if r.CVSS.Valid {
			cvss = r.CVSS.Float64
		}

		published := ""
		if r.Published.Valid {
			published = r.Published.Time.Format(time.RFC3339)
		}

		product := ""
		if r.Product.Valid {
			product = r.Product.String
		}
		fmt.Printf("%d. %s | product=%s | cvss=%.1f | published=%s\n", i+1, r.CVEID, product, cvss, published)
	}
}
