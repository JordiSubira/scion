// Copyright 2019 ETH Zurich
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

package drkey

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = (*Prefetcher)(nil)

// Prefetcher is in charge of getting the level 1 keys before they expire.
type Prefetcher struct {
	LocalIA addr.IA
	Store   drkeystorage.ServiceStore
	// XXX(JordiSubira): At the moment we assume "global" KeyDuration, i.e.
	// every AS involved uses the same EpochDuration. This will be improve
	// further in the future, so that the prefetcher get keys in advance
	// based on the epoch established by the AS which derived the first
	// level key.
	KeyDuration time.Duration
}

// Name returns the tasks name.
func (f *Prefetcher) Name() string {
	return "drkey.Prefetcher"
}

// Run requests the level 1 keys to other CSs.
func (f *Prefetcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	ases, err := f.Store.KnownASes(ctx)
	if err != nil {
		log.Error("Could not prefetch level 1 keys", "error", err)
		return
	}
	log.Debug("Prefetching level 1 DRKeys", "ASes", ases)
	when := time.Now().Add(f.KeyDuration)
	for _, srcIA := range ases {
		srcIA := srcIA
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			getLvl1Key(ctx, f.Store, srcIA, f.LocalIA, when, &wg)
		}()
	}
	wg.Wait()
}

func getLvl1Key(ctx context.Context, store drkeystorage.ServiceStore,
	srcIA, dstIA addr.IA, valTime time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	meta := drkey.Lvl1Meta{
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	_, err := store.GetLvl1Key(ctx, meta, valTime)
	if err != nil {
		log.Error("Failed to prefetch the level 1 key", "remote AS", srcIA.String(), "error", err)
	}
}
