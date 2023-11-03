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

package helpers

import "golang.org/x/tools/container/intsets"

type SparseSetIter[T uint | uint32 | uint64] func(val T) error

type SparseSet[T uint | uint32 | uint64] struct {
	set intsets.Sparse
}

func (s *SparseSet[T]) Copy(val *SparseSet[T]) {
	s.set.Copy(&val.set)
}

func (s *SparseSet[T]) ForEach(fn SparseSetIter[T]) error {
	for _, val := range s.set.AppendTo(nil) {
		if err := fn(T(val)); err != nil {
			return err
		}
	}
	return nil
}

func (s *SparseSet[T]) InsertAll(vals ...T) {
	for _, val := range vals {
		s.Insert(val)
	}
}

func (s *SparseSet[T]) Insert(val T) bool {
	s.validateValue(val)
	return s.set.Insert(int(val))
}

func (s *SparseSet[T]) Intersection(lhs, rhs *SparseSet[T]) {
	if lhs == nil || rhs == nil || lhs.set.IsEmpty() || rhs.set.IsEmpty() {
		s.set.Clear()
	} else {
		s.set.Intersection(&lhs.set, &rhs.set)
	}
}

func (s *SparseSet[T]) IntersectionWith(rhs *SparseSet[T]) {
	if rhs == nil {
		return
	}

	if rhs.set.IsEmpty() {
		s.set.Clear()
	} else {
		s.set.IntersectionWith(&rhs.set)
	}
}

func (s *SparseSet[T]) IsEmpty() bool {
	return s.set.IsEmpty()
}

func (s *SparseSet[T]) validateValue(val T) {
	if uint64(val) > uint64(intsets.MaxInt) {
		panic("integer value exceeds maximum index value")
	}
}
