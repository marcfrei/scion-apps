// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"C"
	"unsafe"

	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

// check just ensures the error is nil, or complains and quits
func check(e error) {
	if e != nil {
		panic(fmt.Sprintf("Fatal error: %v", e))
	}
}

type Client struct {
	sciond sciond.Connector
}

func NewClient(sciondAddr string) Client {
	sciond, err := sciond.NewService(sciondAddr).Connect(context.Background())
	check(err)
	return Client{
		sciond: sciond,
	}
}

func (c Client) HostKey(meta drkey.Lvl2Meta) drkey.Lvl2Key {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// get L2 key: (slow path)
	key, err := c.sciond.DRKeyGetLvl2Key(ctx, meta, time.Now().UTC())
	check(err)
	return key
}

func ThisClientAndMeta(sciondAddr string,
	srcIA addr.IA, srcHost addr.HostAddr, dstIA addr.IA, dstHost addr.HostAddr) (Client, drkey.Lvl2Meta) {
	c := NewClient(sciondAddr)
	meta := drkey.Lvl2Meta{
		KeyType:  drkey.Host2Host,
		Protocol: "piskes",
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	return c, meta
}

type Server struct {
	sciond sciond.Connector
}

func NewServer(sciondAddr string) Server {
	sciond, err := sciond.NewService(sciondAddr).Connect(context.Background())
	check(err)
	return Server{
		sciond: sciond,
	}
}

func (s Server) dsForServer(meta drkey.Lvl2Meta) drkey.DelegationSecret {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	dsMeta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: meta.Protocol,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
	}
	now := time.Now().UTC()
	lvl2Key, err := s.sciond.DRKeyGetLvl2Key(ctx, dsMeta, now)
	check(err)
	fmt.Printf("DS key = %s, epoch = %s\n", hex.EncodeToString(lvl2Key.Key), lvl2Key.Epoch)
	ds := drkey.DelegationSecret{
		Protocol: lvl2Key.Protocol,
		Epoch:    lvl2Key.Epoch,
		SrcIA:    lvl2Key.SrcIA,
		DstIA:    lvl2Key.DstIA,
		Key:      lvl2Key.Key,
	}
	next := lvl2Key.Epoch.NotAfter.Add(1 * time.Second)
	lvl2KeyNext, err := s.sciond.DRKeyGetLvl2Key(ctx, dsMeta, next)
	check(err)
	fmt.Printf("Next DS key = %s, epoch = %s\n", hex.EncodeToString(lvl2KeyNext.Key), lvl2KeyNext.Epoch)
	prev := lvl2Key.Epoch.NotBefore.Add(-1 * time.Second)
	lvl2KeyPrev, err := s.sciond.DRKeyGetLvl2Key(ctx, dsMeta, prev)
	check(err)
	fmt.Printf("Prev DS key = %s, epoch = %s\n", hex.EncodeToString(lvl2KeyPrev.Key), lvl2KeyPrev.Epoch)
	return ds
}

func (s Server) HostKeyFromDS(meta drkey.Lvl2Meta, ds drkey.DelegationSecret) drkey.Lvl2Key {
	piskes := (protocol.KnownDerivations["piskes"]).(protocol.DelegatedDerivation)
	derived, err := piskes.DeriveLvl2FromDS(meta, ds)
	check(err)
	return derived
}

func ThisServerAndMeta(sciondAddr string,
	srcIA addr.IA, srcHost addr.HostAddr, dstIA addr.IA, dstHost addr.HostAddr) (Server, drkey.Lvl2Meta) {
	server := NewServer(sciondAddr)
	meta := drkey.Lvl2Meta{
		KeyType:  drkey.Host2Host,
		Protocol: "piskes",
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	return server, meta
}

var addrRegexp = regexp.MustCompile(`^(\d+-[\d:A-Fa-f]+),\[([^\]]+)\]$`)

const (
	addrRegexpIaIndex = 1
	addrRegexpL3Index = 2
)

func addrFromString(address string) (snet.SCIONAddress, error) {
	parts := addrRegexp.FindStringSubmatch(address)
	if parts == nil {
		return snet.SCIONAddress{}, fmt.Errorf("no valid SCION address: %q", address)
	}
	ia, err := addr.IAFromString(parts[addrRegexpIaIndex])
	if err != nil {
		return snet.SCIONAddress{},
			fmt.Errorf("invalid IA string: %v", parts[addrRegexpIaIndex])
	}
	var l3 addr.HostAddr
	if hostSVC := addr.HostSVCFromString(parts[addrRegexpL3Index]); hostSVC != addr.SvcNone {
		l3 = hostSVC
	} else {
		l3 = addr.HostFromIPStr(parts[addrRegexpL3Index])
		if l3 == nil {
			return snet.SCIONAddress{},
				fmt.Errorf("invalid IP address string: %v", parts[addrRegexpL3Index])
		}
	}
	return snet.SCIONAddress{IA: ia, Host: l3}, nil
}

//export GetDelegationSecret
func GetDelegationSecret(sciondAddr *C.char, srcIA, dstIA uint64, valTime int64,
	validityNotBefore, validityNotAfter *int64, key unsafe.Pointer) {
	sd, err := sciond.NewService(C.GoString(sciondAddr)).Connect(context.Background())
	check(err)

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	dsMeta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "piskes",
		SrcIA:    addr.IAInt(srcIA).IA(),
		DstIA:    addr.IAInt(dstIA).IA(),
	}
	lvl2Key, err := sd.DRKeyGetLvl2Key(ctx, dsMeta, time.Unix(valTime, 0).UTC())
	check(err)

	*validityNotBefore = lvl2Key.Epoch.NotBefore.Unix()
	*validityNotAfter = lvl2Key.Epoch.NotAfter.Unix()
	copy((*[16]byte)(key)[:], lvl2Key.Key)
}

func main() {
	var clientKey, serverKey drkey.Lvl2Key

	var clientRole bool
	var serverRole bool
	var sciondAddr string
	var srcAddr string
	var dstAddr string
	flag.BoolVar(&clientRole, "client", false, "Do client side derivation")
	flag.BoolVar(&serverRole, "server", false, "Do server side derivation")
	flag.StringVar(&sciondAddr, "sciond", "127.0.0.1:30255", "SCIOND address")
	flag.StringVar(&srcAddr, "src", "1-ff00:0:111,[127.0.0.1]", "Source address")
	flag.StringVar(&dstAddr, "dst", "1-ff00:0:112,[fd00:f00d:cafe::7f00:a]", "Destination address")

	flag.Parse()
	if !clientRole && !serverRole {
		clientRole = true
		serverRole = true
	}

	srcSCIONAddr, err := addrFromString(srcAddr)
	if err != nil {
		fmt.Println(err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	dstSCIONAddr, err := addrFromString(dstAddr)
	if err != nil {
		fmt.Println(err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if clientRole {
		client, metaClient := ThisClientAndMeta(sciondAddr, srcSCIONAddr.IA, srcSCIONAddr.Host, dstSCIONAddr.IA, dstSCIONAddr.Host)
		t0 := time.Now()
		clientKey = client.HostKey(metaClient)
		durationClient := time.Since(t0)

		fmt.Printf("Client: key = %s, epoch = %s, duration = %s\n",
			hex.EncodeToString(clientKey.Key), clientKey.Epoch, durationClient)
	}

	if serverRole {
		server, metaServer := ThisServerAndMeta(sciondAddr, srcSCIONAddr.IA, srcSCIONAddr.Host, dstSCIONAddr.IA, dstSCIONAddr.Host)
		ds := server.dsForServer(metaServer)
		t0 := time.Now()
		serverKey = server.HostKeyFromDS(metaServer, ds)
		durationServer := time.Since(t0)

		fmt.Printf("Server: key = %s, epoch = %s, duration = %s\n",
			hex.EncodeToString(serverKey.Key), ds.Epoch, durationServer)
	}
}
