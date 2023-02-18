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
