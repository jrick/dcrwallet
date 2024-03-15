package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"decred.org/dcrwallet/v4/lru"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/container/apbf"
	"github.com/decred/dcrd/wire"
	"go.etcd.io/bbolt"
)

// XXX: still a proof of concept. uses a single flat file per data type.
// TODO: split the flat files out into multiple files (headers0001.fdb,
// headers0002.fdb, etc.) trying to stay under 4GB files.

const (
	bboltDBFilename          = "primary.db"
	txKeysDBFilename         = "txkeys.db"
	headersFlatFilename      = "headers.fdb"
	transactionsFlatFilename = "transactions.fdb"
)

const filePerm = 0600

const txCacheSize = 1000

var (
	headersBucketName      = []byte("h")
	transactionsBucketName = []byte("t")
)

var be = binary.BigEndian

type DB struct {
	directory        string
	bboltDB          *bbolt.DB
	headersFile      *os.File
	transactionsFile *os.File
	mu               sync.Mutex

	// All headers are retained in memory and are written to a flat file,
	// with indexes in this file recorded as values under an incrementing
	// key.
	headers map[chainhash.Hash]*headerEntry

	// Recent transactions are retained in memory (in a LRU), but not the
	// complete set of all wallet transactions.  Like headers,
	// transactions are serialized in flat files.  If a transaction is
	// available in the LRU, no further lookups are necessary.
	//
	// An APBF is used to determine when a transaction is definitely not
	// recorded by the storage database.  However, on a positive filter
	// hit, it is impossible to know for certain whether the transaction
	// is recorded or not.  A separate bbolt database (txKeysDB),
	// recording full transaction hashes to transactions' flat file
	// offsets is used to determine presence with certainty.
	//
	// Due to poor performance characteristics of large bbolt databases on
	// operating systems lacking a unified buffer cache, and the
	// undesirable B+ tree rebalancing that occurs using cryptographic
	// hashes as keys, the txKeysDB database is written to in batches in
	// the background.  The total number of transactions recorded (N)
	// represents the first N transactions sequenced by the primary
	// database.  During Open, any additional transactions recorded in the
	// primary database but missing from txKeysDB are reconciled by adding
	// them to txKeysDB.
	txAPBF   *apbf.Filter
	txLRU    lru.Map[chainhash.Hash, *wire.MsgTx]
	txKeysDB *bbolt.DB
}

type headerEntry struct {
	seq    uint64
	hash   chainhash.Hash
	header *wire.BlockHeader
}

func Open(directory string) (db *DB, err error) {
	// err = os.Mkdir(directory, filePerm|os.ModeDir)
	// if err != nil {
	// 	return nil, err
	// }

	bdb, err := bbolt.Open(filepath.Join(directory, bboltDBFilename), filePerm, bbolt.DefaultOptions)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			bdb.Close()
		}
	}()
	err = bdb.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(headersBucketName)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(transactionsBucketName)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	txKeysDB, err := bbolt.Open(filepath.Join(directory, txKeysDBFilename), filePerm, bbolt.DefaultOptions)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			txKeysDB.Close()
		}
	}()
	err = txKeysDB.Update(func(tx *bbolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists(transactionsBucketName)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	headersFileName := filepath.Join(directory, headersFlatFilename)
	headersFile, err := os.OpenFile(headersFileName, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			headersFile.Close()
		}
	}()
	transactionsFileName := filepath.Join(directory, transactionsFlatFilename)
	transactionsFile, err := os.OpenFile(transactionsFileName, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			transactionsFile.Close()
		}
	}()

	db = &DB{
		directory:        directory,
		bboltDB:          bdb,
		headersFile:      headersFile,
		transactionsFile: transactionsFile,

		headers: make(map[chainhash.Hash]*headerEntry),

		txAPBF:   apbf.NewFilter(txCacheSize, 0.001),
		txLRU:    lru.NewMap[chainhash.Hash, *wire.MsgTx](txCacheSize),
		txKeysDB: txKeysDB,
	}

	var totalTxs uint64
	err = bdb.View(func(tx *bbolt.Tx) error {
		headersBucket := tx.Bucket(headersBucketName)
		txsBucket := tx.Bucket(transactionsBucketName)

		var wantSeq uint64
		err := headersBucket.ForEach(func(k, v []byte) error {
			if len(k) != 8 {
				return fmt.Errorf("header key is not 8 bytes")
			}
			seq := be.Uint64(k)
			if seq != wantSeq {
				return fmt.Errorf("header bucket skips keys")
			}
			wantSeq++

			if len(v) != 8 {
				return fmt.Errorf("header value is not 8 bytes")
			}
			off := int64(be.Uint64(v))
			if off < 0 {
				return fmt.Errorf("header offset is negative")
			}
			header, err := db.readHeaderAtOffset(off)
			if err != nil {
				return err
			}
			hash := header.BlockHash()

			db.headers[hash] = &headerEntry{
				seq:    seq,
				hash:   hash,
				header: header,
			}

			return nil
		})
		if err != nil {
			return err
		}

		wantSeq = 0
		txCount := txsBucket.Stats().KeyN
		if txCount > txCacheSize {
			wantSeq = uint64(txCount) - txCacheSize
		}
		seqKey := make([]byte, 8)
		be.PutUint64(seqKey, wantSeq)
		c := txsBucket.Cursor()
		for k, v := c.Seek(seqKey); k != nil; k, v = c.Next() {
			if len(k) != 8 {
				return fmt.Errorf("transaction key is not 8 bytes")
			}
			seq := be.Uint64(k)
			if seq != wantSeq {
				return fmt.Errorf("transaction bucket skips keys")
			}
			wantSeq++

			if len(v) != 40 {
				return fmt.Errorf("transaction value is not 40 bytes")
			}
			off := int64(be.Uint64(v[:8]))
			vhash := v[8:]

			if off < 0 {
				return fmt.Errorf("transation offset is negative")
			}
			tx, err := db.readTransactionAtOffset(off)
			if err != nil {
				return err
			}
			hash := tx.TxHash()
			if !bytes.Equal(hash[:], vhash) {
				return fmt.Errorf("mismatched transaction hash")
			}

			db.txAPBF.Add(hash[:])
			db.txLRU.Add(hash, tx)

			return nil
		}
		if err != nil {
			return err
		}

		totalTxs = wantSeq

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Reconcile any missing transactions from the txKeysDB.
	var keyedTxCount uint64
	err = db.txKeysDB.View(func(tx *bbolt.Tx) error {
		keyedTxCount = uint64(tx.Bucket(transactionsBucketName).Stats().KeyN)
		return nil
	})
	if err != nil {
		return nil, err
	}
	switch {
	case keyedTxCount > totalTxs:
		return nil, fmt.Errorf("transaction key database records more " +
			"transactions than primary key database")
	case keyedTxCount < totalTxs:
		err := func() (err error) {
			primaryDBTx, err := db.bboltDB.Begin(false)
			if err != nil {
				return err
			}
			defer primaryDBTx.Rollback()

			txKeysDBTx, err := db.txKeysDB.Begin(true)
			if err != nil {
				return err
			}
			defer func() {
				if err == nil {
					err = txKeysDBTx.Commit()
				} else {
					txKeysDBTx.Rollback()
				}
			}()
			txKeysDBBucket := txKeysDBTx.Bucket(transactionsBucketName)

			seq := keyedTxCount
			seqKey := make([]byte, 8)
			be.PutUint64(seqKey[:], seq)
			c := primaryDBTx.Bucket(transactionsBucketName).Cursor()
			for k, v := c.Seek(seqKey); k != nil; k, v = c.Next() {
				off := v[:8]
				hash := v[8:]
				err := txKeysDBBucket.Put(hash, off)
				if err != nil {
					return err
				}
			}

			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

func (db *DB) Close() error {
	db.bboltDB.Close()
}

func (db *DB) readHeaderAtOffset(off int64) (*wire.BlockHeader, error) {
	seeked, err := db.headersFile.Seek(off, 0)
	if err != nil {
		return nil, err
	}
	if seeked != off {
		return nil, fmt.Errorf("unable to seek to headers file offset %v", off)
	}
	header := new(wire.BlockHeader)
	err = header.Deserialize(db.headersFile)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (db *DB) readTransactionAtOffset(off int64) (*wire.MsgTx, error) {
	seeked, err := db.transactionsFile.Seek(off, 0)
	if err != nil {
		return nil, err
	}
	if seeked != off {
		return nil, fmt.Errorf("unable to seek to transactions file offset %v", off)
	}
	tx := new(wire.MsgTx)
	err = tx.Deserialize(db.transactionsFile)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (db *DB) InsertBlockHeader(hash chainhash.Hash, h *wire.BlockHeader) error {
	//db.bboltDB
	panic("todo")
}

func (db *DB) InsertTx(hash chainhash.Hash, tx *wire.MsgTx) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	off, err := db.transactionsFile.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	err = tx.Serialize(db.transactionsFile)
	if err != nil {
		return err
	}
	// File must be synced before database update is committed, but this is
	// done at the end of the transaction.

	go func() {
		err = db.bboltDB.Batch(func(dbtx *bbolt.Tx) error {
			bucket := dbtx.Bucket(transactionsBucketName)
			seq := bucket.Sequence()
			if err != nil {
				return err
			}
			seqKey := make([]byte, 8)
			be.PutUint64(seqKey, seq)

			v := make([]byte, 40)
			be.PutUint64(v[:8], uint64(off))
			copy(v[8:], hash[:])

			bucket.Put(seqKey, v)

			// Increment sequence for next update (so our sequences begin
			// at zero).
			bucket.NextSequence()

			err = db.transactionsFile.Sync()
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			//return err
		}
	}()

	go func() {
		err := db.txKeysDB.Batch(func(dbtx *bbolt.Tx) error {
			bucket := dbtx.Bucket(transactionsBucketName)
			v := make([]byte, 8)
			be.PutUint64(v, uint64(off))
			bucket.Put(hash[:], v)
			return nil
		})
		if err != nil {
			panic("XXX figure out what to do with this error")
		}
	}()

	return nil
}
