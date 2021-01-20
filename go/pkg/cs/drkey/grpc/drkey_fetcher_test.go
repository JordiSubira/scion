// Copyright 2021 ETH Zurich
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

package grpc_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	dk_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc"
	mock_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc/mock_grpc"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func TestGetLvl1FromOtherCS(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	epochBegin, err := ptypes.TimestampProto(util.SecsToTime(0))
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(util.SecsToTime(1))
	require.NoError(t, err)
	key := xtest.MustParseHexString("7f8e507aecf38c09e4cb10a0ff0cc497")

	testCases := map[string]struct {
		req       *dkpb.DRKeyLvl1Request
		rep       *dkpb.DRKeyLvl1Response
		getter    func(ctrl *gomock.Controller) dk_grpc.Lvl1KeyGetter
		assertErr assert.ErrorAssertionFunc
	}{
		"valid": {
			getter: func(ctrl *gomock.Controller) dk_grpc.Lvl1KeyGetter {
				rep := &dkpb.DRKeyLvl1Response{
					EpochBegin: epochBegin,
					EpochEnd:   epochEnd,
					Drkey:      key,
				}
				getter := mock_grpc.NewMockLvl1KeyGetter(ctrl)
				getter.EXPECT().GetLvl1Key(gomock.Any(), gomock.Eq(srcIA), gomock.Any()).Return(rep, nil)
				return getter
			},
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			fetcher := dk_grpc.DRKeyFetcher{
				Getter: tc.getter(ctrl),
			}

			_, err := fetcher.GetLvl1FromOtherCS(context.Background(), srcIA, dstIA, time.Now())
			tc.assertErr(t, err)
		})
	}
}
