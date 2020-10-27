package wallet

import (
	"context"

	"decred.org/dcrwallet/wallet/walletdb"
)

func (w *Wallet) Rollback(ctx context.Context, height int32) error {
	return walletdb.Update(ctx, w.db, func(dbtx walletdb.ReadWriteTx) error {
		return w.txStore.Rollback(dbtx, height)
	})
}
