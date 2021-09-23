// Package mobile provides wrappers to wallet and SPV functionality suitable for
// creating iOS and Android libraries.
//
// Bindings will occasionally appear strange or inefficient due to type
// restrictions of the binding generator
// (https://godoc.org/golang.org/x/mobile/cmd/gobind#hdr-Type_restrictions).
//
// Care must be taken to avoid reference cycles between languages.  Do not hold
// references to Go types from interface implementers in target languages
// (https://godoc.org/golang.org/x/mobile/cmd/gobind#hdr-Avoid_reference_cycles).
//
// 'go generate' directives are provided for generating bindings.  The ios and
// android build tags enable the directives for each respective platform.
//
// Example usage (requires project in GOPATH):
//
//  $ GO111MODULE=on go mod download
//  $ GO111MODULE=on go mod vendor
//  $ GO111MODULE=off go generate -tags ios # Builds Mobile.framework for org.decred.Decred-Wallet
//  $ GO111MODULE=off go generate -tags android # Builds mobile.aar
//
// iOS builds require Xcode and a Mac.  Android builds requires a JDK in PATH
// and the Android NDK to be installed at $ANDROID_HOME/ndk-bundle or
// $ANDROID_NDK_HOME.
package mobile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"

	"decred.org/dcrwallet/v2/errors"
	"decred.org/dcrwallet/v2/p2p"
	"decred.org/dcrwallet/v2/spv"
	"decred.org/dcrwallet/v2/wallet"
	"decred.org/dcrwallet/v2/wallet/txauthor"
	"decred.org/dcrwallet/v2/wallet/txrules"
	"decred.org/dcrwallet/v2/walletseed"
	"github.com/decred/dcrd/addrmgr/v2"
	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/gcs/v3"
	blockcf "github.com/decred/dcrd/gcs/v3/blockcf2"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
	"github.com/decred/slog"

	_ "decred.org/dcrwallet/v2/wallet/drivers/bdb"
)

// Logger collects all log output from all subsystems.
type Logger interface {
	// Log receives log lines as they are produced by the wallet.
	// Logs include trailing newline characters and are encoded as UTF-8.
	// Implementers of Log must return quickly as Log will block calling code.
	Log(l []byte)
}

type logWriter struct {
	Logger

	// This mutex can be removed if SetLogger is only called once at startup.
	mu sync.Mutex
}

func (l *logWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	logger := l.Logger
	l.mu.Unlock()
	if logger != nil {
		logger.Log(b)
	}
	return len(b), nil
}

var logger = new(logWriter)

// SetLogger sends all configured log output to l.
// Should only be called once at program startup.
func SetLogger(l Logger) {
	logger.mu.Lock()
	logger.Logger = l
	logger.mu.Unlock()
}

func init() {
	backend := slog.NewBackend(logger)
	wallet.UseLogger(backend.Logger("WLLT"))
	spv.UseLogger(backend.Logger("SYNC"))
	p2p.UseLogger(backend.Logger("SYNC"))
	addrmgr.UseLogger(backend.Logger("AMGR"))
}

// Context wraps Go's context.Context in a way suitable to generate mobile
// bindings.
type Context struct {
	ctx    context.Context
	cancel func()
}

// ContextBackground wraps Go's context.Background.
func ContextBackground() *Context {
	return &Context{ctx: context.Background()}
}

// ContextBackground wraps Go's context.WithCancel.
func ContextWithCancel(ctx *Context) *Context {
	child, cancel := context.WithCancel(ctx.ctx)
	return &Context{ctx: child, cancel: cancel}
}

// Cancel calls the context's cancel func, if any exists.
func (c *Context) Cancel() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Wallet exposes wallet and syncing functionality for mobile devices.
type Wallet struct {
	wallet *wallet.Wallet
	dir    string
	db     wallet.DB
	notifs *spv.Notifications
	syncer *spv.Syncer
	cancel func()
	mu     sync.Mutex // protects syncer and cancel
}

// nopanic prevents panics crossing a language boundary.
// When panicing, e is assigned an error from the recovered object.
func nopanic(e *error) {
	if r := recover(); r != nil {
		switch r := r.(type) {
		case error:
			*e = r
		case string:
			*e = errors.E(r)
		default:
			*e = errors.Errorf("%s", r)
		}
	}
}

var oob = errors.E("value out-of-bounds")

func boundUint32(v int64) (uint32, error) {
	if v < 0 || v > int64(^uint32(0)) {
		return 0, oob
	}
	return uint32(v), nil
}

// CoinNet enumerates supported Decred networks.
type CoinNet = int64

// Decred networks
const (
	Mainnet CoinNet = iota
	Testnet3
)

var errNoCoinnet = errors.E("unknown coinnet")

func coinnetParams(coinnet CoinNet) (*chaincfg.Params, error) {
	switch coinnet {
	case Mainnet:
		return chaincfg.MainNetParams(), nil
	case Testnet3:
		return chaincfg.TestNet3Params(), nil
	default:
		return nil, errNoCoinnet
	}
}

var pubPass = []byte(wallet.InsecurePubPassphrase)

const dbFile = "wallet.db"

// CreateWallet creates a new wallet in directory dir from seed and passphrase.
// Skipping initial address discovery and rescanning steps is a permitted
// optimization.  Use RestoreWallet to prevent this behavior.
func CreateWallet(coinnet CoinNet, dir string, seed, passphrase []byte) (_ *Wallet, err error) {
	return RestoreWallet(coinnet, dir, seed, passphrase) // No difference yet.
}

// RestoreWallet creates a new wallet in directory dir from seed and passphrase.
// It differs from CreateWallet by never skipping the initial restoring steps.
func RestoreWallet(coinnet CoinNet, dir string, seed, passphrase []byte) (_ *Wallet, err error) {
	defer nopanic(&err)

	params, err := coinnetParams(coinnet)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(dir, os.ModeDir|0700)
	if err != nil {
		return nil, err
	}
	db, err := wallet.CreateDB("bdb", filepath.Join(dir, dbFile))
	if err != nil {
		return nil, err
	}
	err = wallet.Create(context.Background(), db, pubPass, passphrase, seed, params)
	if err != nil {
		return nil, err
	}

	return openDB(db, dir, params)
}

func openDB(db wallet.DB, dir string, params *chaincfg.Params) (*Wallet, error) {
	cfg := &wallet.Config{
		DB:              db,
		PubPassphrase:   pubPass,
		GapLimit:        wallet.DefaultGapLimit,
		AccountGapLimit: wallet.DefaultAccountGapLimit,
		Params:          params,
	}
	ww, err := wallet.Open(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	ww.SetRelayFee(txrules.DefaultRelayFeePerKb) // Because Config uses float64

	w := &Wallet{
		wallet: ww,
		dir:    dir,
		db:     db,
		notifs: new(spv.Notifications),
	}
	return w, nil
}

// OpenWallet opens an existing wallet database in the directory dir.
func OpenWallet(coinnet CoinNet, dir string) (_ *Wallet, err error) {
	defer nopanic(&err)

	params, err := coinnetParams(coinnet)
	if err != nil {
		return nil, err
	}

	db, err := wallet.OpenDB("bdb", filepath.Join(dir, dbFile))
	if err != nil {
		return nil, err
	}

	return openDB(db, dir, params)
}

// Close closes the wallet database.  Must only be called when there is no
// ongoing database transaction.
func (w *Wallet) Close() (err error) {
	defer nopanic(&err)

	return w.db.Close()
}

// NewSeed creates a random 32-byte seed.
// Use SeedMnemonic to return the mnemonic of this seed.
func NewSeed() (seed []byte, err error) {
	defer nopanic(&err)

	seed = make([]byte, 32)
	_, err = rand.Read(seed)
	return
}

// SeedMnemonic returns a 33-word, space-separated, checksummed, PGP word list
// encoding of a 32-byte seed.
func SeedMnemonic(seed []byte) (mnemonic string, err error) {
	defer nopanic(&err)

	return walletseed.EncodeMnemonic(seed), nil
}

// DecodeSeed decodes a seed from hex or checksummed PGP word list form to
// bytes.
func DecodeSeed(userInput string) (seed []byte, err error) {
	defer nopanic(&err)

	return walletseed.DecodeUserInput(userInput)
}

// Unlock allows private keys and other wallet secrets to be used.
func (w *Wallet) Unlock(passphrase []byte) (err error) {
	defer nopanic(&err)

	return w.wallet.Unlock(context.Background(), passphrase, nil)
}

// Lock prevents private keys and other wallet secrets from being used.
func (w *Wallet) Lock() (err error) {
	defer nopanic(&err)

	w.wallet.Lock()
	return nil
}

// IsLocked returns whether the wallet is currently passphrase locked.
func (w *Wallet) IsLocked() (locked bool, err error) {
	defer nopanic(&err)

	return w.wallet.Locked(), nil
}

// ChangePassphrase changes the passphrase from old to new.
// The wallet will remain in the same locked or unlocked state as it
// was before the change.
func (w *Wallet) ChangePassphrase(old, new []byte) (err error) {
	defer nopanic(&err)

	return w.wallet.ChangePrivatePassphrase(context.Background(), old, new)
}

// MainChainTipHash returns the block hash of the best chain tip the wallet
// is aware of.
func (w *Wallet) MainChainTipHash() (hash []byte, err error) {
	defer nopanic(&err)

	h, _ := w.wallet.MainChainTip(context.Background())
	return h[:], nil
}

// RescanPoint returns the block hash at which a rescan should begin to sync
// missing transactions relative to the best known block header, or nil if no
// rescan is necessary and the transactions are synced through the main chain
// tip block.
func (w *Wallet) RescanPoint() (hash []byte, err error) {
	defer nopanic(&err)

	h, err := w.wallet.RescanPoint(context.Background())
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, nil
	}
	return h[:], nil
}

// RescanProgressNotifier receives notifications of rescan progress.
type RescanProgressNotifier interface {
	RescanProgress(height int32)
}

// Rescan manually performs a rescan of the wallet.  This rescan is not
// synchronized with the network syncing perfored by the SPV syncer, but must be
// called while the SPV syncer is running so that full blocks can be downloaded
// as needed.
func (w *Wallet) Rescan(ctx *Context, from int32, notifier RescanProgressNotifier) (err error) {
	defer nopanic(&err)

	w.mu.Lock()
	syncer := w.syncer
	w.mu.Unlock()
	if syncer == nil {
		return errNotSyncing
	}

	progress := make(chan wallet.RescanProgress, 1)

	var background sync.Mutex
	background.Lock()
	var backgroundErr error
	go func() {
		defer background.Unlock()
		defer nopanic(&backgroundErr)
		w.wallet.RescanProgressFromHeight(ctx.ctx, syncer, from, progress)
	}()

	for p := range progress {
		if p.Err != nil {
			return err
		}
		notifier.RescanProgress(p.ScannedThrough)
	}

	background.Lock()
	return backgroundErr
}

// BlockInfo describes details about a block and its relation to the wallet's
// chain state.
type BlockInfo struct {
	Height           int32
	Timestamp        int64
	MainChain        bool
	StakeInvalidated bool
}

// BlockInfo returns more details about a block, querying by its hash.
func (w *Wallet) BlockInfo(hash []byte) (_ *BlockInfo, err error) {
	defer nopanic(&err)

	var h chainhash.Hash
	copy(h[:], hash)

	header, err := w.wallet.BlockHeader(context.Background(), &h)
	if err != nil {
		return nil, err
	}
	mainchain, invalidated, err := w.wallet.BlockInMainChain(context.Background(), &h)
	if err != nil {
		return nil, err
	}
	info := &BlockInfo{
		Height:           int32(header.Height),
		Timestamp:        header.Timestamp.Unix(),
		MainChain:        mainchain,
		StakeInvalidated: invalidated,
	}
	return info, nil
}

// UnbundleProgressNotifier receives notifications of unbundle activity.
type UnbundleProgressNotifier interface {
	UnbundleProgress(lastHeaderHeight int32, lastHeaderTime int64)
}

// Unbundle decompresses block headers and version 2 cfilters from a file
// and connects them to the wallet's main chain.
//
// If notifier is non-nil, its methods are called to notify progress.
func (w *Wallet) Unbundle(ctx *Context, file string, notifier UnbundleProgressNotifier) (err error) {
	defer nopanic(&err)

	fi, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fi.Close()
	z, err := gzip.NewReader(fi)
	if err != nil {
		return err
	}
	flen := make([]byte, 4)
	forest := new(wallet.SidechainForest)
	for {
		if err := ctx.ctx.Err(); err != nil {
			return err
		}
		header := new(wire.BlockHeader)
		err := header.Deserialize(z)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = io.ReadFull(z, flen)
		if err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(flen)
		if n > 1<<20 {
			return errors.Errorf("filter size %v is insanely high", n)
		}
		filter := make([]byte, n)
		_, err = io.ReadFull(z, filter)
		if err != nil {
			return err
		}

		blockHash := header.BlockHash()
		have, _, err := w.wallet.BlockInMainChain(ctx.ctx, &blockHash)
		if err != nil {
			return err
		}
		if have {
			continue
		}
		f, err := gcs.FromBytesV2(blockcf.B, blockcf.M, filter)
		if err != nil {
			return err
		}
		node := wallet.NewBlockNode(header, &blockHash, f)
		forest.AddBlockNode(node)
		best, err := w.wallet.EvaluateBestChain(ctx.ctx, forest)
		if err != nil {
			return err
		}
		if len(best) < 2000 {
			continue
		}
		_, err = w.wallet.ChainSwitch(ctx.ctx, forest, best, nil)
		if err != nil {
			return err
		}
		if notifier != nil {
			last := best[len(best)-1].Header
			notifier.UnbundleProgress(int32(last.Height), last.Timestamp.Unix())
		}
	}
	best, err := w.wallet.EvaluateBestChain(ctx.ctx, forest)
	if err != nil {
		return err
	}
	if len(best) > 0 {
		_, err = w.wallet.ChainSwitch(ctx.ctx, forest, best, nil)
		if err != nil {
			return err
		}
		if notifier != nil {
			last := best[len(best)-1].Header
			notifier.UnbundleProgress(int32(last.Height), last.Timestamp.Unix())
		}
	}
	z.Close()
	return nil
}

var errSyncing = errors.E("already syncing")

// SPVSync synchronizes the wallet using committed filter SPV.
// Returns when CancelSync is called or an unexpected error is encountered.
func (w *Wallet) SPVSync() (err error) {
	return w.spvSync(nil)
}

// SPVSyncWith synchronizes the wallet using committed filter SPV from a single specified peer.
// Returns when CancelSync is called or an unexpected error is encountered.
func (w *Wallet) SPVSyncWith(peer string) (err error) {
	return w.spvSync([]string{peer})
}

func (w *Wallet) spvSync(peers []string) (err error) {
	defer nopanic(&err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.mu.Lock()
	if w.cancel != nil {
		w.mu.Unlock()
		return errSyncing
	}
	params := w.wallet.ChainParams()
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	amgr := addrmgr.New(w.dir, net.LookupIP)
	lp := p2p.NewLocalPeer(params, addr, amgr)
	syncer := spv.NewSyncer(w.wallet, lp)
	syncer.SetPersistentPeers(peers)
	w.cancel = cancel
	w.syncer = syncer
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.syncer = nil
		w.cancel = nil
		w.mu.Unlock()
		if err == context.Canceled {
			err = nil
		}
		w.wallet.SetNetworkBackend(nil)
	}()

	w.wallet.SetNetworkBackend(syncer)
	syncer.SetNotifications(w.notifs)
	return syncer.Run(ctx)
}

var errNotSyncing = errors.E("not syncing")

// CancelSync cancels the synchronization processes performed by SPVSync and
// causes SPVSync to exit without error.
func (w *Wallet) CancelSync() (err error) {
	defer nopanic(&err)

	defer w.mu.Unlock()
	w.mu.Lock()
	if w.cancel == nil {
		return errNotSyncing
	}
	w.cancel()
	w.cancel = nil
	return nil
}

// DiscoverUsage performs address and/or account discovery.
// The wallet must be actively syncing for this operation to complete.
// If startBlockHash is exactly 32 bytes long, discovery will occur starting
// from this block.  Otherwise, all blocks in the chain are searched for usage.
// When discoverAccounts is true, discovery will occur for to find account usage
// for accounts which have not yet been derived by this wallet.  This feature
// requires the wallet to be unlocked so that hardened account keys may be derived.
func (w *Wallet) DiscoverUsage(c *Context, startBlockHash []byte, discoverAccounts bool) error {
	w.mu.Lock()
	syncer := w.syncer
	w.mu.Unlock()
	if syncer == nil {
		return errNotSyncing
	}

	startBlock := w.wallet.ChainParams().GenesisHash
	if len(startBlockHash) == 32 {
		copy(startBlock[:], startBlockHash)
	}

	return w.wallet.DiscoverActiveAddresses(c.ctx, syncer, &startBlock,
		discoverAccounts, wallet.DefaultGapLimit)
}

// GapPolicy describes if and how new addresses should be returned when
// returning the next unused address would violate the gap limit.
type GapPolicy = int64

const (
	GapPolicyError  GapPolicy = iota // Return error if next address violates unused address gap limit
	GapPolicyWrap                    // When the gap is exhausted, wrap around and return a previously-returned address
	GapPolicyIgnore                  // Return the next address without wrapping
)

var errNoGapPolicy = errors.E("unknown gap policy")

// Branch specifies the account branch (external or internal).
type Branch = int32

const (
	BranchExternal Branch = iota // External branch (for addresses given to others)
	BranchInternal               // Internal branch (for internally-derive addresses, such as change)
)

// NextAddress returns the next address for an account, respecting the required
// gap limit policy.  Gap limits should not be ignored without user consent due
// to subsequent reseeds possibly requiring manual intervention.
//
// account must be representable by an unsigned 32-bit integer.
func (w *Wallet) NextAddress(account int64, branch Branch, gapPolicy GapPolicy) (_ string, err error) {
	defer nopanic(&err)

	accountU32, err := boundUint32(account)
	if err != nil {
		return "", err
	}

	newAddress := w.wallet.NewExternalAddress
	switch branch {
	case 0:
	case 1:
		newAddress = w.wallet.NewInternalAddress
	default:
		return "", errors.E("branch must be 0 (external) or 1 (internal)")
	}

	var policy wallet.NextAddressCallOption
	switch gapPolicy {
	case GapPolicyError:
		policy = wallet.WithGapPolicyError()
	case GapPolicyWrap:
		policy = wallet.WithGapPolicyWrap()
	case GapPolicyIgnore:
		policy = wallet.WithGapPolicyIgnore()
	default:
		return "", errNoGapPolicy
	}

	a, err := newAddress(context.TODO(), accountU32, policy)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

type ValidateAddressResult struct {
	Mine    bool
	Account int64 // Value will be bound to a uint32
}

// ValidateAddress decodes an address, returning an error if decode fails.
// If decoding succeeds, a result is returned which specifies whether the address
// is controlled by this wallet, and if so, which account.
func (w *Wallet) ValidateAddress(address string) (*ValidateAddressResult, error) {
	res := new(ValidateAddressResult)
	addr, err := stdaddr.DecodeAddress(address, w.wallet.ChainParams())
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	ka, err := w.wallet.KnownAddress(ctx, addr)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			// No additional information available about the address.
			return res, nil
		}
		return nil, err
	}
	account, err := w.wallet.AccountNumber(ctx, ka.AccountName())
	if err != nil {
		return nil, err
	}
	res.Mine = true
	res.Account = int64(account)
	return res, nil
}

// LastSequentialAccount returns the last sequential BIP0044 numeric account ID.
// This method does not return reserved high account numbers such as for the
// imported account.
//
// account will be representable by an unsigned 32-bit integer.
func (w *Wallet) LastSequentialAcount() (account int64, err error) {
	defer nopanic(&err)

	// TODO: This is stupid.  Export the udb method from wallet package.
	accounts, err := w.wallet.Accounts(context.Background())
	if err != nil {
		return 0, err
	}
	for _, res := range accounts.Accounts[1:] {
		if res.AccountNumber == uint32(account+1) {
			account = int64(res.AccountNumber)
			continue
		}
		break
	}
	return
}

// Amount describes a Decred amount counted in atoms (1 DCR = 1e8 atoms).
type Amount = int64

// AtomsToDCR converts atoms to the floating point representation, valued in DCR.
func AtomsToDCR(v Amount) float64 {
	return dcrutil.Amount(v).ToCoin()
}

// DCRToAtoms converts the floating point representation, valued in DCR, to atoms.
func DCRToAtoms(v float64) (Amount, error) {
	atoms, err := dcrutil.NewAmount(v)
	return Amount(atoms), err
}

// Balances describes the balances of a wallet or account.
// All values report balances in atoms (1 DCR = 1e8 atoms).
type Balances struct {
	ImmatureCoinbaseRewards Amount
	ImmatureStakeGeneration Amount
	LockedByTickets         Amount
	Spendable               Amount
	Total                   Amount
	VotingAuthority         Amount
	Unconfirmed             Amount
}

func marshalBalances(in *wallet.Balances) *Balances {
	return &Balances{
		ImmatureCoinbaseRewards: int64(in.ImmatureCoinbaseRewards),
		ImmatureStakeGeneration: int64(in.ImmatureStakeGeneration),
		LockedByTickets:         int64(in.LockedByTickets),
		Spendable:               int64(in.Spendable),
		Total:                   int64(in.Total),
		VotingAuthority:         int64(in.VotingAuthority),
		Unconfirmed:             int64(in.Unconfirmed),
	}
}

// AccountBalances returns the current balances of account, with spendable and
// unconfirmed balances calculated relative to the required confirmation depth.
//
// account must be representable by an unsigned 32-bit integer.
func (w *Wallet) AccountBalances(account int64, confirms int32) (bal *Balances, err error) {
	defer nopanic(&err)

	accountU32, err := boundUint32(account)
	if err != nil {
		return nil, err
	}

	res, err := w.wallet.AccountBalance(context.Background(), accountU32, confirms)
	if err != nil {
		return nil, err
	}
	return marshalBalances(&res), nil
}

// AccountName returns the current name associated with account.
//
// account must be representable by an unsigned 32-bit integer.
func (w *Wallet) AccountName(account int64) (_ string, err error) {
	defer nopanic(&err)

	accountU32, err := boundUint32(account)
	if err != nil {
		return "", err
	}

	return w.wallet.AccountName(context.Background(), accountU32)
}

// RenameAccount sets the name for an account number to newName.
//
// account must be representable by an unsigned 32-bit integer.
func (w *Wallet) RenameAccount(account int64, newName string) (err error) {
	defer nopanic(&err)

	a, err := boundUint32(account)
	if err != nil {
		return err
	}

	return w.wallet.RenameAccount(context.Background(), a, newName)
}

// CreateAccount creates and names the next sequential account.
// The wallet must be unlocked for this call to succeed.
//
// account will be representable by an unsigned 32-bit integer.
func (w *Wallet) CreateAccount(name string) (account int64, err error) {
	defer nopanic(&err)

	id, err := w.wallet.NextAccount(context.Background(), name)
	return int64(id), err
}

// Tx queries for a transaction by its hash, and returns a Tx binding if found.
// Returns nil if the transaction was not found.
func (w *Wallet) Tx(hash []byte) (_ *Tx, err error) {
	defer nopanic(&err)

	if len(hash) != 32 {
		return nil, errors.E("hash has wrong length")
	}

	h := new(chainhash.Hash)
	copy(h[:], hash)
	summary, _, blockHash, err := w.wallet.TransactionSummary(context.Background(), h)
	if err != nil {
		if errors.Is(err, errors.NotExist) {
			return nil, nil
		}
		return nil, err
	}

	var height int32 = -1
	if blockHash != nil {
		id := wallet.NewBlockIdentifierFromHash(blockHash)
		info, err := w.wallet.BlockInfo(context.Background(), id)
		if err != nil {
			return nil, err
		}
		height = info.Height
	}

	var blockHashBytes []byte
	if blockHash != nil {
		blockHashBytes = blockHash[:]
	}
	return makeTx(summary, height, blockHashBytes, w.wallet.ChainParams())
}

func makeTx(summary *wallet.TransactionSummary, height int32, blockHash []byte, params *chaincfg.Params) (*Tx, error) {
	m := new(wire.MsgTx)
	err := m.Deserialize(bytes.NewReader(summary.Transaction))
	if err != nil {
		return nil, err
	}
	mine := make(map[uint64]uint32)
	for i := range summary.MyInputs {
		in := &summary.MyInputs[i]
		mine[myInputMask|uint64(in.Index)] = in.PreviousAccount
	}
	for i := range summary.MyOutputs {
		out := &summary.MyOutputs[i]
		mine[myOutputMask|uint64(out.Index)] = out.Account
	}

	t := &Tx{
		m:           m,
		mine:        mine,
		hash:        summary.Hash[:],
		blockHeight: height,
		blockHash:   blockHash,
		time:        summary.Timestamp,
		params:      params,
	}
	return t, nil
}

// TxType enumerates transaction types.
type TxType = int64

// Transaction types
const (
	TxTypeRegular TxType = iota
	TxTypeTicket
	TxTypeVote
	TxTypeRevocation
)

const myInputMask = 0
const myOutputMask = 1 << 63

// Tx binds properties of a raw transaction and associated wallet data.
//
// Note that this type does not hold a reference to the wallet and is not updated
// as the transaction is mined or is placed in different blocks across a reorg.
// New Tx instances must be used to query corrected values pertaining to the block
// when the transaction appears in a new block.
type Tx struct {
	m *wire.MsgTx

	// mine records relevant accounts of input or output indexes (outputs | 1<<63).
	// The value is copied to returned TxIn/TxOut instances.
	// Irrelevant outputs are not recorded.
	mine map[uint64]uint32

	hash        []byte
	blockHeight int32
	blockHash   []byte
	time        int64
	params      *chaincfg.Params
}

// Hash returns the 32-byte hash identifying the transaction.
// Use HashString to return the byte-reversed string representation.
func (t *Tx) Hash() []byte {
	return t.hash
}

// HashString returns the byte-reversed hex representation of the transaction hash.
//
// Consider implementing this in target code to avoid unnecessary native calls.
func (t *Tx) HashString() string {
	return HashString(t.Hash())
}

// BlockHeight returns the block height Tx is mined in.
// A height of -1 indicates the transaction is (or was) unmined.
func (t *Tx) BlockHeight() int32 {
	return t.blockHeight
}

// BlockHash returns the block hash Tx is mined in.
// A nil value indicates the transaction is (or was) unmined.
func (t *Tx) BlockHash() []byte {
	return t.blockHash
}

// Time returns the Unix timestamp the wallet associated with the transaction.
func (t *Tx) Time() int64 {
	return t.time
}

// Type returns the transaction type (regular, ticket, vote, or revocation).
func (t *Tx) Type() TxType {
	const treasury = true
	const autoRevokes = false
	switch stake.DetermineTxType(t.m, treasury, autoRevokes) {
	case stake.TxTypeRegular:
		return TxTypeRegular
	case stake.TxTypeSStx:
		return TxTypeTicket
	case stake.TxTypeSSGen:
		return TxTypeVote
	case stake.TxTypeSSRtx:
		return TxTypeRevocation
	default:
		return TxTypeRegular
	}
}

// Version returns the transaction version.
// The value will be bound by an unsigned 16-bit integer.
func (t *Tx) Version() int32 {
	return int32(t.m.Version)
}

// LockTime returns the transaction's lock time.
// The value will be bound by an unsigned 32-bit integer.
func (t *Tx) LockTime() int64 {
	return int64(t.m.LockTime)
}

// Expiry returns the transaction's expiry.
// The value will be bound by an unsigned 32-bit integer
func (t *Tx) Expiry() int64 {
	return int64(t.m.Expiry)
}

// NumInputs returns the number of transaction inputs.
// The result will be non-negative.
func (t *Tx) NumInputs() int32 {
	return int32(len(t.m.TxIn))
}

// NumOutputs returns the number of transaction outputs.
// The result will be non-negative.
func (t *Tx) NumOutputs() int32 {
	return int32(len(t.m.TxOut))
}

// TxIn returns the transaction input at index (0-based).
// Errors if the input does not exist.
func (t *Tx) TxIn(index int32) (*TxIn, error) {
	i := int(index)
	if i < 0 || i >= len(t.m.TxIn) {
		return nil, oob
	}
	account, mine := t.mine[myInputMask|uint64(index)]
	in := &TxIn{
		m:       t.m.TxIn[i],
		mine:    mine,
		account: account,
	}
	return in, nil
}

// TxIn returns the transaction output at index (0-based).
// Errors if the output does not exist.
func (t *Tx) TxOut(index int32) (*TxOut, error) {
	i := int(index)
	if i < 0 || i >= len(t.m.TxOut) {
		return nil, oob
	}
	account, mine := t.mine[myOutputMask|uint64(index)]
	out := &TxOut{
		m:       t.m.TxOut[i],
		mine:    mine,
		account: account,
		params:  t.params,
	}
	return out, nil
}

// TxIn binds properties of a raw transaction input and associated wallet data.
type TxIn struct {
	m       *wire.TxIn
	mine    bool
	account uint32
}

// Mine returns whether this transaction input is controlled by this wallet.
func (in *TxIn) Mine() bool {
	return in.mine
}

// Account records the account the input is associated with.
// This value is only relevant when Mine is true.
// The value will be bound by a 32-bit unsigned integer.
func (in *TxIn) Account() int64 {
	return int64(in.account)
}

// AmountUnknown describes an input amount which is not known due to details of
// transaction serialization and signature creation in version 1 transactions.
const AmountUnknown Amount = -1

// Amount returns the input amount of a transaction input.
// Warning: Not all input amounts may be set by version 1 transactions.
// Compare against AmountUnknown before using this value.
func (in *TxIn) Amount() Amount {
	return Amount(in.m.ValueIn)
}

// TxOut binds properties of a raw transaction output and associated wallet data.
type TxOut struct {
	m       *wire.TxOut
	mine    bool
	account uint32
	params  *chaincfg.Params
}

// Mine returns whether this transaction output is controlled by this wallet.
func (out *TxOut) Mine() bool {
	return out.mine
}

// Account records the account the output is associated with.
// This value is only relevant when Mine is true.
// The value will be bound by a 32-bit unsigned integer.
func (out *TxOut) Account() int64 {
	return int64(out.account)
}

// Script returns the transaction output script.
func (out *TxOut) Script() []byte {
	return out.m.PkScript
}

// ScriptVersion returns the version of an output script.
// The value will be bound by a 16-bit unsigned integer.
func (out *TxOut) ScriptVersion() int32 {
	return int32(out.m.Version)
}

// Address decodes the transaction script and version into a recognized address format, if possible.
// Returns the empty string if the script is nonstandard or otherwise unrecognized.
func (out *TxOut) Address() string {
	switch out.m.Version {
	case 0:
		const treasury = true
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(0, out.m.PkScript,
			out.params, treasury)
		if err != nil || len(addrs) == 0 {
			return ""
		}
		return addrs[0].String()
	default:
		return ""
	}
}

// Amount returns the output amount.
func (out *TxOut) Amount() Amount {
	return Amount(out.m.Value)
}

// TxSlice provides random access to a read-only slice of Tx elements.
type TxSlice struct {
	txs []*Tx
}

// Len returns the number of elements of the slice.
func (t *TxSlice) Len() int {
	return len(t.txs)
}

// N accesses the nth element of the slice.
func (t *TxSlice) N(n int) (*Tx, error) {
	if n < 0 || n >= len(t.txs) {
		return nil, oob
	}
	return t.txs[n], nil
}

// TxIter iterates wallet transactions one block at a time.
// For a consistent view of the wallet's transaction history between
// Prev/Next calls, use the iterator before starting the SPV syncer.
type TxIter struct {
	wallet *wallet.Wallet
	height int32
	err    error
	elem   *BlockedTxs
}

// TxIterAtHeight returns a TxIter which will iterate beginning at the block
// described by height, or mempool if height is -1.
func (w *Wallet) TxIterAtHeight(height int32) *TxIter {
	return &TxIter{
		wallet: w.wallet,
		height: height,
	}
}

// BlockedTxs records relevant wallet transactions in a block or mempool.
type BlockedTxs struct {
	BlockHeight int32  // -1 for mempool txs
	BlockHash   []byte // nil for mempool txs
	Txs         *TxSlice
}

// Elem returns the current block or mempool element.
// Prev must have been called and returned true for this element to be valid.
func (t *TxIter) Elem() (*BlockedTxs, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.elem == nil {
		return nil, errors.E("no elem")
	}
	return t.elem, nil
}

// Err returns an error returned or recovered during transaction iteration.
// It should be used following a loop.
func (t *TxIter) Err() error {
	return t.err
}

const (
	endPrev = -2
	endNext = -3 // Will be used if Next method is added
)

// Prev moves the iterator backwards, returning BlockedTxs from the
// next-most-recent block or mempool.
// It returns true if items transactions were read (available by
// calling Elem), and false otherwise.
func (t *TxIter) Prev() (ok bool) {
	defer func() {
		nopanic(&t.err)
		ok = t.err == nil && t.elem != nil
	}()

	t.elem = nil

	if t.height == endPrev || t.err != nil {
		return
	}

	begin := t.height
	if begin == endNext {
		begin = -1
	}

	params := t.wallet.ChainParams()
	f := func(block *wallet.Block) (bool, error) {
		t.elem = new(BlockedTxs)
		if block.Header == nil {
			t.elem.BlockHeight = -1
		} else {
			hash := block.Header.BlockHash()
			t.elem.BlockHash = hash[:]
			t.elem.BlockHeight = int32(block.Header.Height)
		}
		txs := make([]*Tx, 0, len(block.Transactions))
		for i := range block.Transactions {
			tx, err := makeTx(&block.Transactions[i], t.elem.BlockHeight, t.elem.BlockHash, params)
			if err != nil {
				return false, err
			}
			txs = append(txs, tx)
		}
		t.elem.Txs = &TxSlice{txs}
		return true, nil // call f no more than once
	}

	beginID := wallet.NewBlockIdentifierFromHeight(begin)
	endID := wallet.NewBlockIdentifierFromHeight(0)
	err := t.wallet.GetTransactions(context.Background(), f, beginID, endID)
	if err != nil {
		t.err = err
		return
	}

	if t.elem == nil {
		return
	}

	if t.elem.BlockHeight == 0 {
		t.height = endPrev
	} else if t.elem.BlockHeight == -1 {
		_, t.height = t.wallet.MainChainTip(context.Background())
	} else {
		t.height = t.elem.BlockHeight - 1
	}

	return
}

// AuthoredTx represents an in-construction transaction.
// Funding the AuthoredTx will add select wallet inputs to spend from the
// transaction, including a transaction fee and adding a change output if necessary.
// Outputs must be added and shuffled before it is passed to Sign.
// After signing, the transaction may be published to the network and recorded
// by the wallet.
type AuthoredTx struct {
	outs     []*wire.TxOut
	algo     wallet.OutputSelectionAlgorithm
	atx      *txauthor.AuthoredTx
	change   txauthor.ChangeSource
	fee      Amount
	signedTx []byte
	params   *chaincfg.Params
}

func (w *Wallet) NewAuthoredTx() *AuthoredTx {
	return &AuthoredTx{
		outs:   make([]*wire.TxOut, 0, 2),
		params: w.wallet.ChainParams(),
	}
}

// OutputSelection specifies the algorithm to use when selecting
// outputs to construct a transaction.
type OutputSelection = int

const (
	// OutputSelectionDefault describes the default output selection
	// algorithm.  It is not optimized for any particular use case.
	OutputSelectionDefault OutputSelection = wallet.OutputSelectionAlgorithmDefault

	// OutputSelectionAll describes the output selection algorithm of
	// picking every possible available output.  This is useful for sweeping.
	OutputSelectionAll OutputSelection = wallet.OutputSelectionAlgorithmAll
)

// SetOutputSelection sets the algorithm used when selecting inputs during funding.
func (a *AuthoredTx) SetOutputSelection(algo OutputSelection) {
	a.algo = wallet.OutputSelectionAlgorithm(algo)
}

// AddOutput adds an output paying amount to the transaction script
// represented by address.
func (a *AuthoredTx) AddOutput(address string, amount Amount) (err error) {
	defer nopanic(&err)

	if amount < 0 {
		return errors.E("amount must be positive")
	}
	if amount > dcrutil.MaxAmount {
		return errors.E("amount exceeds maximum")
	}

	addr, err := stdaddr.DecodeAddress(address, a.params)
	if err != nil {
		return err
	}
	vers, script := addr.PaymentScript()
	out := wire.NewTxOut(amount, script)
	out.Version = vers
	a.outs = append(a.outs, out)
	a.atx = nil
	a.fee = 0
	a.signedTx = nil
	return nil
}

// SetChangeAddress sets the change address used when adding a change
// output during funding.  This method is commonly used when the
// output selection algorithm is set to all, in order to "sweep" all
// funds from an account in a single transaction through a single change
// output.
//
// If address is the empty string, any change script associated with the
// AuthoredTx is cleared.
func (a *AuthoredTx) SetChangeAddress(address string) (err error) {
	defer nopanic(&err)

	if address == "" {
		a.change = nil
		return nil
	}

	addr, err := stdaddr.DecodeAddress(address, a.params)
	if err != nil {
		return err
	}
	vers, script := addr.PaymentScript()

	a.change = &changeSource{
		script:  script,
		version: vers,
	}
	return nil
}

// Reset removes all in-progress outputs and funding from the AuthoredTx.
// If previous funding created a change address, or a change address was
// manually set, this address (which will be unused if the previous
// transaction was not published) is not cleared and may be used by further
// funding.  To reset the change address as well, create a new AuthoredTx
// or call SetChangeAddress("").
func (a *AuthoredTx) Reset() {
	a.outs = a.outs[:0]
	a.algo = wallet.OutputSelectionAlgorithmDefault
	a.atx = nil
	a.fee = 0
	a.signedTx = nil
}

// Fee returns the transaction fee.  This method returns 0 if the transaction
// has not been funded yet.
func (a *AuthoredTx) Fee() Amount {
	return a.fee
}

// EstimatedSignedSerializeSize returns the estimated size of the transaction after
// signatures are added.
func (a *AuthoredTx) EstimatedSignedSerializeSize() (_ int, err error) {
	defer nopanic(&err)

	if a.atx == nil || a.fee == 0 {
		return 0, errors.E("not funded")
	}
	return a.atx.EstimatedSignedSerializeSize, nil
}

// Hash returns the 32-byte hash identifying the transaction.
// The transaction must be funded for the hash to be valid.
// Signing a transaction does not modify the hash.
// Use HashString to return the byte-reversed string representation.
func (a *AuthoredTx) Hash() (_ []byte, err error) {
	defer nopanic(&err)

	if a.fee == 0 || a.atx == nil {
		return nil, errors.E("not funded")
	}
	hash := a.atx.Tx.TxHash()
	return hash[:], nil
}

// HashString returns the byte-reversed hex representation of the transaction hash.
// The transaction must be funded for the hash to be valid.
// Signing a transaction does not modify the hash.
//
// Consider implementing this in target code to avoid unnecessary native calls.
func (a *AuthoredTx) HashString() (string, error) {
	hash, err := a.Hash()
	if err != nil {
		return "", err
	}
	return HashString(hash), nil
}

var shuffleRand *mathrand.Rand
var shuffleMu sync.Mutex

func init() {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	seed := int64(binary.LittleEndian.Uint64(buf))
	shuffleRand = mathrand.New(mathrand.NewSource(seed))
}

func shuffle(n int, swap func(i, j int)) {
	shuffleMu.Lock()
	shuffleRand.Shuffle(n, swap)
	shuffleMu.Unlock()
}

// Shuffle cryptographically shuffles the inputs and outputs of the transaction.
// This should be performed to increase privacy by making it more difficult
// to determine which of the outputs is change.
// This should be done after funding but before signing, so signatures are not
// invalidated.
func (a *AuthoredTx) Shuffle() (err error) {
	defer nopanic(&err)

	if a.fee == 0 || a.atx == nil {
		return errors.E("tx is not funded")
	}

	shuffle(len(a.atx.Tx.TxIn), func(i, j int) {
		a.atx.Tx.TxIn[i], a.atx.Tx.TxIn[j] = a.atx.Tx.TxIn[j], a.atx.Tx.TxIn[i]
	})
	shuffle(len(a.atx.Tx.TxOut), func(i, j int) {
		a.atx.Tx.TxOut[i], a.atx.Tx.TxOut[j] = a.atx.Tx.TxOut[j], a.atx.Tx.TxOut[i]
		if a.atx.ChangeIndex == i || a.atx.ChangeIndex == j {
			// Keep ChangeIndex valid whenever change moves positions.
			// XORs cancel such that ChangeIndex set to i if equal to j, or j if equal to i.
			a.atx.ChangeIndex ^= i ^ j
		}
	})
	return nil
}

type changeSource struct {
	script  []byte
	version uint16
}

func (c *changeSource) Script() (script []byte, version uint16, err error) {
	return c.script, c.version, nil
}

func (c *changeSource) ScriptSize() int {
	return len(c.script)
}

// Fund adds inputs to an AuthoredTx from the wallet's unspent transaction
// output (UTXO) set.  Account identifies the account the selected UTXOs
// come from.  Minconf describes the minimum number of block confirmations
// before an output may be considered.  feePerKB describes the fee rate, in
// DCR/kB of estimated signed transaction size, with the calculated fee being
// subtracted from a change output.
//
// account must be representable by an unsigned 32-bit integer.
func (w *Wallet) Fund(tx *AuthoredTx, account int64, minconf int32, feePerKB Amount) (err error) {
	defer nopanic(&err)

	accountU32, err := boundUint32(account)
	if err != nil {
		return err
	}

	tx.signedTx = nil
	tx.atx, err = w.wallet.NewUnsignedTransaction(context.Background(), tx.outs,
		dcrutil.Amount(feePerKB), accountU32, minconf, tx.algo, tx.change, nil)
	if err != nil {
		return err
	}
	// Reuse change for any future calls if new change was made.
	if tx.change == nil && tx.atx.ChangeIndex != -1 {
		out := tx.atx.Tx.TxOut[tx.atx.ChangeIndex]
		tx.change = &changeSource{
			script:  out.PkScript,
			version: out.Version,
		}
	}

	input := int64(tx.atx.TotalInput)
	var output int64
	for _, out := range tx.atx.Tx.TxOut {
		output += out.Value
	}
	if output > input {
		return errors.E("invalid tx: more output value than input value")
	}
	tx.fee = input - output
	return nil
}

// SignAuthoredTx uses wallet keys to add input signatures to an AuthoredTx.
// The wallet must be unlocked and the transaction must be funded for this
// method to complete successfully.
func (w *Wallet) SignAuthoredTx(tx *AuthoredTx) (err error) {
	defer nopanic(&err)

	if tx.fee == 0 {
		return errors.E("not funded")
	}

	errs, err := w.wallet.SignTransaction(context.Background(), tx.atx.Tx, txscript.SigHashAll, nil, nil, nil)
	if err != nil {
		return err
	}
	if len(errs) != 0 {
		return errors.Errorf("input %d: %v", errs[0].InputIndex, errs[0].Error)
	}

	signedTx := new(bytes.Buffer)
	signedTx.Grow(tx.atx.Tx.SerializeSize())
	err = tx.atx.Tx.Serialize(signedTx)
	if err != nil {
		return err
	}
	tx.signedTx = signedTx.Bytes()

	return
}

// PublishAuthoredTx records the signed AuthoredTx in the wallet's transaction
// history and publishes the transaction to the network.
//
// The SPV syncer must be running for this method to complete successfully.
func (w *Wallet) PublishAuthoredTx(tx *AuthoredTx) (err error) {
	defer nopanic(&err)

	if tx.signedTx == nil {
		return errors.E("not signed")
	}

	w.mu.Lock()
	syncer := w.syncer
	w.mu.Unlock()
	if syncer == nil {
		return errors.E(errors.NoPeers, "not syncing")
	}
	_, err = w.wallet.PublishTransaction(context.TODO(), tx.atx.Tx, syncer)
	tx.change = nil
	return err
}

// HashString returns the byte-reversed hex representation of a hash.
//
// Consider implementing this in target code to avoid unnecessary native calls.
func HashString(hash []byte) string {
	r := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r[31-i] = hash[i]
	}
	return hex.EncodeToString(r)
}

// StringToHash returns the unreversed bytes of a 32-byte hash.
//
// Consider implementing this in target code to avoid unnecessary native calls.
func StringToHash(hash string) ([]byte, error) {
	h, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	if len(h) != 32 {
		return nil, errors.E("hash has wrong length")
	}
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return h, nil
}

// Confirmations returns the number of confirmations of a block or transaction
// relative to the height of the chain tip.
//
// Consider implementing this in target code to avoid unnecessary native calls.
func Confirmations(height, tipHeight int32) int32 {
	switch {
	case height == -1, height > tipHeight:
		return 0
	default:
		return tipHeight - height + 1
	}
}

// SyncedNotifier receives changes to the sync status as parameters.
type SyncedNotifier interface {
	Synced(synced bool)
}

func (w *Wallet) NotifySynced(n SyncedNotifier) {
	w.notifs.Synced = n.Synced
}

// PeerNotifier receives notifications of peer counts and connected/disconnected
// peers as parameters.
type PeerNotifier interface {
	PeerConnected(peerCount int32, addr string)
	PeerDisconnected(peerCount int32, addr string)
}

func (w *Wallet) NotifyPeers(n PeerNotifier) {
	w.notifs.PeerConnected = n.PeerConnected
	w.notifs.PeerDisconnected = n.PeerDisconnected
}

// FetchHeadersNotifier receives notifications of header fetching activity.
type FetchHeadersNotifier interface {
	FetchHeadersStarted()
	FetchHeadersProgress(lastHeaderHeight int32, lastHeaderTime int64)
	FetchHeadersFinished()
}

func (w *Wallet) NotifyFetchHeaders(n FetchHeadersNotifier) {
	w.notifs.FetchHeadersStarted = n.FetchHeadersStarted
	w.notifs.FetchHeadersProgress = n.FetchHeadersProgress
	w.notifs.FetchHeadersFinished = n.FetchHeadersFinished
}

// RescanNotifier receives notifications of rescan activity.
type RescanNotifier interface {
	RescanStarted()
	RescanProgress(height int32)
	RescanFinished()
}

func (w *Wallet) NotifyRescanProgress(n RescanNotifier) {
	w.notifs.RescanStarted = n.RescanStarted
	w.notifs.RescanProgress = n.RescanProgress
	w.notifs.RescanFinished = n.RescanFinished
}

// AddressDiscoveryNotifier receives notifications of address discovery
// activity.
type AddressDiscoveryNotifier interface {
	DiscoverAddressesStarted()
	DiscoverAddressesFinished()
}

func (w *Wallet) NotifyAddressDiscovery(n AddressDiscoveryNotifier) {
	w.notifs.DiscoverAddressesStarted = n.DiscoverAddressesStarted
	w.notifs.DiscoverAddressesFinished = n.DiscoverAddressesFinished
}

// MempoolTxNotifier receives notifications of new unmined transactions
// relevant to and saved by the wallet.
type MempoolTxNotifier interface {
	MempoolTx(tx *Tx)
}

func (w *Wallet) NotifyMempoolTx(n MempoolTxNotifier) {
	w.notifs.MempoolTxs = func(txs []*wire.MsgTx) {
		for _, tx := range txs {
			hash := tx.TxHash()
			t, _ := w.Tx(hash[:])
			if t != nil {
				n.MempoolTx(t)
			}
		}
	}
}

// TipChangedNotifier receives notifications of the current best block.
// When reorgDepth is zero, the new block is a direct child of the previous tip.
// If non-zero, one or more blocks described by the parameter were removed from
// the previous main chain.
// txs contains all relevant transactions mined in each attached block in
// unspecified order.
// height and reorgDepth are guaranteed to be non-negative.
type TipChangedNotifier interface {
	TipChanged(hash []byte, height, reorgDepth int32, txs *TxSlice)
}

func (w *Wallet) NotifyTipChanged(n TipChangedNotifier) {
	w.notifs.TipChanged = func(tip *wire.BlockHeader, reorgDepth int32, minedTxs []*wire.MsgTx) {
		txs := make([]*Tx, 0, len(minedTxs))
		for _, minedTx := range minedTxs {
			hash := minedTx.TxHash()
			tx, _ := w.Tx(hash[:])
			if tx != nil {
				txs = append(txs, tx)
			}
		}
		hash := tip.BlockHash()
		n.TipChanged(hash[:], int32(tip.Height), reorgDepth, &TxSlice{txs})
	}
}
