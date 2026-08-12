//go:build !((darwin && (amd64 || arm64)) || (freebsd && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (windows && (386 || amd64 || arm64)))

package admission

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

func openSQLiteAdmissionDatabase(_ context.Context, path string) (*sql.DB, error) {
	db, err := driver.Open(path, func(connection *sqlite3.Conn) error {
		if err := connection.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
			return fmt.Errorf("set sqlite admission busy timeout: %w", err)
		}
		if err := connection.Exec("PRAGMA journal_mode = WAL;"); err != nil {
			return fmt.Errorf("set sqlite admission journal mode: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite admission database: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
