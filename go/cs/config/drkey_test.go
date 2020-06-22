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

package config

import (
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyConfig
	cfg.InitDefaults()
	assert.EqualValues(t, 24*time.Hour, cfg.EpochDuration.Duration)
	assert.EqualValues(t, 2*time.Second, cfg.MaxReplyAge.Duration)
}

func TestDRKeyConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyConfig
	cfg.Sample(&sample, nil, nil)
	meta, err := toml.Decode(sample.String(), &cfg)
	require.NoError(t, err)
	require.Empty(t, meta.Undecoded())
	err = cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, DefaultEpochDuration, cfg.EpochDuration.Duration)
	assert.Equal(t, DefaultMaxReplyAge, cfg.MaxReplyAge.Duration)
}

func TestDisable(t *testing.T) {
	var cfg = NewDRKeyConfig()
	require.False(t, cfg.Enabled())
	var err error
	err = cfg.Validate()
	require.NoError(t, err)
	cfg.EpochDuration.Duration = 10 * time.Hour
	cfg.MaxReplyAge.Duration = 10 * time.Hour
	cfg.DRKeyDB["connection"] = "a"
	cfg.DRKeyDB["backend"] = "sqlite"
	cfg.InitDefaults()
	require.True(t, cfg.Enabled())
	err = cfg.Validate()
	require.NoError(t, err)
	assert.EqualValues(t, 10*time.Hour, cfg.EpochDuration.Duration)
	assert.EqualValues(t, 10*time.Hour, cfg.MaxReplyAge.Duration)
}
