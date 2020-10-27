//+build ignore

package main

import (
	"context"
	"flag"
	"log"
	"path/filepath"

	"decred.org/dcrwallet/wallet"
	_ "decred.org/dcrwallet/wallet/drivers/bdb"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
)

var defaultDBPath = filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "testnet3", "wallet.db")

var (
	db     = flag.String("db", defaultDBPath, "path to wallet.db")
	height = flag.Int("height", -1, "height to begin removing blocks from (inclusive)")
)

func main() {
	flag.Parse()
	if *height < 0 {
		log.Fatal("must set positive -height")
	}
	ctx := context.Background()
	db, err := wallet.OpenDB("bdb", *db)
	if err != nil {
		log.Fatal(err)
	}
	w, err := wallet.Open(ctx, &wallet.Config{
		DB:            db,
		PubPassphrase: []byte("public"),
		Params:        chaincfg.TestNet3Params(),
	})
	if err != nil {
		log.Fatal(err)
	}
	err = w.Rollback(ctx, int32(*height))
	if err != nil {
		log.Fatal(err)
	}
	err = db.Close()
	if err != nil {
		log.Fatal(err)
	}
}
