package mobile

import (
	"io/ioutil"
	"os"
	"testing"
)

func tempWallet(t *testing.T, net CoinNet) (w *Wallet, teardown func()) {
	seed := make([]byte, 32)
	pass := []byte("pass")
	dir, err := ioutil.TempDir("", "dcrwallet-mobile")
	if err != nil {
		t.Fatal(err)
	}
	w, err = CreateWallet(net, dir, seed, pass)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	return w, func() {
		w.Close()
		os.RemoveAll(dir)
	}
}

const mainnetBlock4000 = "0000000000001dcddfe404569a7b8abb11a53aef48908795eef36212a371bfd4"

func TestUnbundle(t *testing.T) {
	w, teardown := tempWallet(t, Mainnet)
	defer teardown()
	ctx := ContextBackground()
	err := w.Unbundle(ctx, "./testdata/mainnet-bundle-4000.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := w.wallet.MainChainTip(ctx.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hash.String() != mainnetBlock4000 {
		t.Fatalf("wrong expected tip block %v", hash)
	}
}
