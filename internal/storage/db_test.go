package storage

import (
	"os"
	"testing"

	"github.com/decred/dcrd/wire"
)

func TestTorture(t *testing.T) {
	dir, err := os.MkdirTemp("", "torture")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("dir: %v", dir)

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	const n = 500_000
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, 0, make([]byte, 108)))
	tx.AddTxOut(wire.NewTxOut(0, make([]byte, 25)))
	for i := int64(0); i < n; i++ {
		tx.TxOut[0].Value = i
		txHash := tx.TxHash()

		db.InsertTx(txHash, tx)
	}
}
