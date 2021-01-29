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

package trust

import (
	"context"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

type KeyProvider struct {
	Dir string
}

func (k KeyProvider) GetKeys(ctx context.Context) ([][]byte, error) {
	logger := log.FromCtx(ctx)

	files, err := filepath.Glob(filepath.Join(k.Dir, "*.key"))
	if err != nil {
		return nil, serrors.WrapStr("loading key files from dir", err)
	}
	logger.Debug("available keys:", "files", files, "dir", filepath.Join(k.Dir, "*.key"))

	var keys [][]byte
	for _, file := range files {
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			logger.Debug("Error reading key file", "file", file, "err", err)
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" {
			continue
		}
		keys = append(keys, block.Bytes)
	}
	return keys, nil
}
