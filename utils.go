/*******************************************************************************
*   (c) 2023 ECAD Labs Inc.
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package goblst

import (
	"crypto"
	"fmt"
	"sync"
	"sync/atomic"
)

func runInParallel(n int, fn func(i int) error) error {
	if n == 0 {
		return nil
	} else if n == 1 {
		return fn(0)
	}
	var (
		wg     sync.WaitGroup
		hasErr int32
		err    error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			e := fn(i)
			if atomic.CompareAndSwapInt32(&hasErr, 0, 1) {
				err = e
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	return err
}

type Scheme int

const (
	Basic Scheme = iota
	Augmentation
)

func (Scheme) HashFunc() crypto.Hash {
	return 0
}

func (s Scheme) SuiteG(g int) []byte {
	switch s {
	case Basic:
		return []byte(fmt.Sprintf("BLS_SIG_BLS12381G%d_XMD:SHA-256_SSWU_RO_NUL_", g))
	case Augmentation:
		return []byte(fmt.Sprintf("BLS_SIG_BLS12381G%d_XMD:SHA-256_SSWU_RO_AUG_", g))
	default:
		return make([]byte, 0)
	}
}
