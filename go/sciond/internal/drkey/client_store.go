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
	"database/sql"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// Drkey fetching errors.
var (
	ErrDB        = serrors.New("error with DB")
	ErrInsertDB  = serrors.New("error inserting in DB")
	ErrMessenger = serrors.New("error with Messenger")
)

type DRKeyLvl2Requester interface {
	GetDRKeyLvl2(ctx context.Context, msg *drkey_mgmt.Lvl2Req, a net.Addr,
		id uint64) (*drkey_mgmt.Lvl2Rep, error)
}

// ClientStore is the DRKey store used in the client side, i.e. sciond.
// It implements drkeystorage.ClientStore.
type ClientStore struct {
	ia        addr.IA
	db        drkey.Lvl2DB
	requester DRKeyLvl2Requester
}

var _ drkeystorage.ClientStore = &ClientStore{}

// NewClientStore constructs a new client store without assigned messenger.
func NewClientStore(local addr.IA, db drkey.Lvl2DB, requester DRKeyLvl2Requester) *ClientStore {
	return &ClientStore{
		ia:        local,
		db:        db,
		requester: requester,
	}
}

// GetLvl2Key returns the level 2 drkey from the local DB or if not found, by asking our local CS.
func (s *ClientStore) GetLvl2Key(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (drkey.Lvl2Key, error) {

	logger := log.FromCtx(ctx)
	// is it in storage?
	k, err := s.db.GetLvl2Key(ctx, meta, util.TimeToSecs(valTime))
	if err == nil {
		return k, err
	}
	if err != sql.ErrNoRows {
		return drkey.Lvl2Key{}, serrors.Wrap(ErrDB, err)
	}
	logger.Trace("[DRKey ClientStore] Level 2 key not stored. Requesting it to CS")
	// if not, ask our CS for it
	req := drkey_mgmt.NewLvl2ReqFromMeta(meta, valTime)
	csAddress := &snet.SVCAddr{IA: s.ia, SVC: addr.SvcCS}
	rep, err := s.requester.GetDRKeyLvl2(ctx, &req, csAddress, messenger.NextId())
	if err != nil {
		return drkey.Lvl2Key{}, serrors.Wrap(ErrMessenger, err)
	}
	k = rep.ToKey(meta)
	if err = s.db.InsertLvl2Key(ctx, k); err != nil {
		logger.Error("[DRKey ClientStore] Could not insert level 2 in DB", "error", err)
		return k, serrors.Wrap(ErrInsertDB, err)
	}
	return k, nil
}

// DeleteExpiredKeys will remove any expired keys.
func (s *ClientStore) DeleteExpiredKeys(ctx context.Context) (int, error) {
	i, err := s.db.RemoveOutdatedLvl2Keys(ctx, util.TimeToSecs(time.Now()))
	return int(i), err
}
