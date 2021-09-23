package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
	"github.com/jrick/wsrpc/v2"
)

var (
	stopFlag = flag.Int("stop", 0, "stop after height")
	ws       = flag.String("ws", "wss://localhost:9109/ws", "JSON-RPC websocket")
	user     = flag.String("u", "", "RPC user")
	pass     = flag.String("p", "", "RPC pass")
	cert     = flag.String("c", filepath.Join(dcrutil.AppDataDir("dcrd", false), "rpc.cert"), "RPC certificate")
)

type block struct {
	header wire.BlockHeader
	filter []byte
}

func main() {
	flag.Parse()

	cert, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	tc := &tls.Config{
		RootCAs: pool,
	}
	ctx := context.Background()
	rpc, err := wsrpc.Dial(ctx, *ws, wsrpc.WithBasicAuth(*user, *pass), wsrpc.WithTLSConfig(tc))
	if err != nil {
		log.Fatal(err)
	}

	z, _ := gzip.NewWriterLevel(os.Stdout, gzip.BestCompression)
	defer func() {
		err := z.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	var genesis string
	err = rpc.Call(ctx, "getblockhash", &genesis, 0)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("genesis block %v", genesis)

	var stop [32]byte
	var res struct {
		Headers []string `json:"headers"`
	}
	locators := []string{genesis}
	var lastHeight int32
	for {
		err = rpc.Call(ctx, "getheaders", &res, locators, hex.EncodeToString(stop[:]))
		if err != nil {
			log.Fatal(err)
		}

		blocks := make([]block, len(res.Headers))
		var wg sync.WaitGroup
		wg.Add(len(res.Headers))
		for i, h := range res.Headers {
			i, h := i, h
			go func() {
				defer wg.Done()
				err := blocks[i].header.Deserialize(hex.NewDecoder(
					strings.NewReader(h)))
				if err != nil {
					log.Fatal(err)
				}

				var filter string
				err = rpc.Call(ctx, "getcfilterv2", &filter,
					blocks[i].header.BlockHash().String())
				if err != nil {
					log.Fatal(err)
				}
				blocks[i].filter, err = hex.DecodeString(filter)
				if err != nil {
					log.Fatal(err)
				}
			}()
		}
		wg.Wait()

		if int32(blocks[0].header.Height) != lastHeight+1 {
			log.Fatal("reorg")
		}
		lastHeight = int32(blocks[len(blocks)-1].header.Height)

		scratch := make([]byte, 4)
		for i := range blocks {
			err := blocks[i].header.Serialize(z)
			if err != nil {
				log.Fatal(err)
			}
			binary.BigEndian.PutUint32(scratch, uint32(len(blocks[i].filter)))
			_, err = z.Write(scratch)
			if err != nil {
				log.Fatal(err)
			}
			_, err = z.Write(blocks[i].filter)
			if err != nil {
				log.Fatal(err)
			}
		}

		last := &blocks[len(blocks)-1]
		log.Printf("processed %v blocks ending at %v/%v", len(blocks),
			last.header.Height, last.header.BlockHash())

		locators = []string{last.header.BlockHash().String()}
		res.Headers = nil

		if int32(last.header.Height) >= int32(*stopFlag) {
			break
		}
	}
}
