//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers_test

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/backends/inmem/helpers"
)

func Test_sparseSet_iteration(t *testing.T) {
	var set helpers.SparseSet[uint32]
	vals := []uint32{3, 5, 7, 9}
	set.InsertAll(vals...)

	var collect []uint32
	set.ForEach(func(val uint32) error {
		collect = append(collect, val)
		return nil
	})
	if !reflect.DeepEqual(vals, collect) {
		t.Errorf("expected %v but received %v", vals, collect)
	}
}
