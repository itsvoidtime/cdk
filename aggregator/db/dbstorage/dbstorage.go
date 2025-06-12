package dbstorage

import (
	"context"
	"database/sql"

	"github.com/agglayer/aggkit/db"
	dbtypes "github.com/agglayer/aggkit/db/types"
)

// DBStorage implements the Storage interface
type DBStorage struct {
	DB *sql.DB
}

// NewDBStorage creates a new DBStorage instance
func NewDBStorage(dbPath string) (*DBStorage, error) {
	db, err := db.NewSQLiteDB(dbPath)
	if err != nil {
		return nil, err
	}

	return &DBStorage{DB: db}, nil
}

func (d *DBStorage) BeginTx(ctx context.Context, options *sql.TxOptions) (dbtypes.Txer, error) {
	return db.NewTx(ctx, d.DB)
}

func (d *DBStorage) getExecQuerier(dbTx dbtypes.Txer) dbtypes.Querier {
	if dbTx == nil {
		return d.DB
	}

	return dbTx
}
