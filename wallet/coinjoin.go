package wallet

// import (
// 	"context"

// 	"decred.org/dcrwallet/v4/errors"
// 	"decred.org/dcrwallet/v4/wallet/walletdb"
// 	"github.com/decred/dcrd/dcrec"
// 	"github.com/decred/dcrd/dcrec/secp256k1/v4"
// 	"github.com/decred/dcrd/dcrutil/v4"
// 	"github.com/decred/dcrd/mixing"
// 	"github.com/decred/dcrd/mixing/mixpool"
// 	"github.com/decred/dcrd/mixing/utxoproof"
// 	"github.com/decred/dcrd/txscript/v4"
// 	"github.com/decred/dcrd/txscript/v4/sign"
// 	"github.com/decred/dcrd/txscript/v4/stdaddr"
// 	"github.com/decred/dcrd/txscript/v4/stdscript"
// 	"github.com/decred/dcrd/wire"
// )

// type coinjoin struct {
// 	tx            *wire.MsgTx
// 	txInputs      map[wire.OutPoint]int
// 	myPrevScripts [][]byte
// 	myIns         []*wire.TxIn
// 	myUTXOs       []wire.MixPRUTXO
// 	change        *wire.TxOut
// 	mcount        int
// 	genScripts    [][]byte
// 	genIndex      []int
// 	inputAmount   int64
// 	amount        int64
// 	wallet        *Wallet
// 	mixAccount    uint32
// 	mixBranch     uint32

// 	ctx context.Context
// }

// func (w *Wallet) newCsppJoin(ctx context.Context, change *wire.TxOut, amount dcrutil.Amount,
// 	mixAccount, mixBranch uint32, mcount int) *coinjoin {

// 	cj := &coinjoin{
// 		tx:         &wire.MsgTx{Version: 1},
// 		change:     change,
// 		mcount:     mcount,
// 		amount:     int64(amount),
// 		wallet:     w,
// 		mixAccount: mixAccount,
// 		mixBranch:  mixBranch,
// 		ctx:        ctx,
// 	}
// 	if change != nil {
// 		cj.tx.TxOut = append(cj.tx.TxOut, change)
// 	}
// 	return cj
// }

// func (w *Wallet) addCoinJoinTxIn(ctx context.Context, c *coinjoin, prevScript []byte,
// 	prevScriptVersion uint16, in *wire.TxIn, expires int64) error {

// 	sc, addrs := stdscript.ExtractAddrs(prevScriptVersion, prevScript,
// 		w.chainParams)
// 	if sc != stdscript.STPubKeyHashEcdsaSecp256k1 {
// 		w.lockedOutpointMu.Unlock()
// 		return errors.E(errors.Invalid, "unsupported script type")
// 	}
// 	prevAddr := addrs[0]

// 	var priv *secp256k1.PrivateKey
// 	var done func()
// 	defer func() {
// 		if done != nil {
// 			done()
// 		}
// 	}()

// 	err := walletdb.View(ctx, w.db, func(dbtx walletdb.ReadTx) error {
// 		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)

// 		var err error
// 		priv, done, err = w.manager.PrivateKey(addrmgrNs, prevAddr)
// 		return err
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	pub := priv.PubKey().SerializeCompressed()
// 	keyPair := utxoproof.Secp256k1KeyPair{
// 		Pub:  pub,
// 		Priv: priv,
// 	}
// 	proofSig, err := keyPair.SignUtxoProof(expires)
// 	if err != nil {
// 		return err
// 	}

// 	c.tx.TxIn = append(c.tx.TxIn, in)
// 	c.myPrevScripts = append(c.myPrevScripts, prevScript)
// 	c.myIns = append(c.myIns, in)
// 	c.myUTXOs = append(c.myUTXOs, wire.MixPRUTXO{
// 		OutPoint:  in.PreviousOutPoint,
// 		Script:    nil, // Only for spending P2SH outputs (not supported by this client)
// 		PubKey:    pub,
// 		Signature: proofSig,
// 	})
// 	c.inputAmount += in.ValueIn
// 	return nil
// }
