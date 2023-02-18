package minsig

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"sort"

	blst "github.com/ecadlabs/goblst"
)

type PrivateKey blst.Scalar

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return nil, fmt.Errorf("blst: %w", err)
	}
	s, err := blst.GenerateKey(buf[:])
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(s), nil
}

func GenerateKeyFrom(ikm []byte) (*PrivateKey, error) {
	s, err := blst.GenerateKey(ikm)
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(s), nil
}

func PrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	if s, err := blst.ScalarFromBytes(data); err != nil {
		return nil, err
	} else {
		return (*PrivateKey)(s), nil
	}
}

func Sign(priv *PrivateKey, digest []byte, scheme blst.Scheme) *Signature {
	var aug []byte
	if scheme == blst.Augmentation {
		aug = priv.PublicKey().Bytes()
	}
	hash := blst.HashToP1(digest, scheme.SuiteG(1), aug)
	return (*Signature)((*blst.Scalar)(priv).SignInG2Affine(hash))
}

func Verify(pub *PublicKey, digest []byte, sig *Signature, scheme blst.Scheme) error {
	return sig.Verify(pub, digest, scheme)
}

func AggregateVerify(items []*PubDigestPair, sig *Signature, scheme blst.Scheme) error {
	return sig.AggregateVerify(items, scheme)
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme := blst.Basic
	if s, ok := opts.(blst.Scheme); ok {
		scheme = s
	}
	return Sign(priv, digest, scheme).Bytes(), nil
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return (*PublicKey)((*blst.Scalar)(priv).P2Affine())
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey()
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	if other, ok := x.(*PrivateKey); ok {
		return (*blst.Scalar)(priv).Equal((*blst.Scalar)(other))
	}
	return false
}

type PublicKey blst.P2Affine

func PublicKeyFromBytes(data []byte) (*PublicKey, error) {
	if a, err := blst.DecompressP2Affine(data); err != nil {
		return nil, err
	} else {
		return (*PublicKey)(a), nil
	}
}

func (pub *PublicKey) IsValid() error {
	switch {
	case (*blst.P2Affine)(pub).IsInf():
		return blst.ErrPkIsInfinity
	case !(*blst.P2Affine)(pub).IsInG2():
		return blst.ErrPointNotInGroup
	default:
		return nil
	}
}

func (pub *PublicKey) IsOnCurve() bool {
	return (*blst.P2Affine)(pub).IsOnCurve()
}

func (pub *PublicKey) Bytes() []byte {
	return (*blst.P2Affine)(pub).Compress()
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	if other, ok := x.(*PublicKey); ok {
		return (*blst.P2Affine)(pub).Equal((*blst.P2Affine)(other))
	}
	return false
}

type Signature blst.P1Affine

func SignatureFromBytes(data []byte) (*Signature, error) {
	if a, err := blst.DecompressP1Affine(data); err != nil {
		return nil, err
	} else {
		return (*Signature)(a), nil
	}
}

func (sig *Signature) Bytes() []byte {
	return (*blst.P1Affine)(sig).Compress()
}

func (sig *Signature) IsValid() error {
	switch {
	case (*blst.P1Affine)(sig).IsInf():
		return blst.ErrPkIsInfinity
	case !(*blst.P1Affine)(sig).IsInG1():
		return blst.ErrPointNotInGroup
	default:
		return nil
	}
}

func (sig *Signature) Verify(pub *PublicKey, digest []byte, scheme blst.Scheme) error {
	var aug []byte
	if scheme == blst.Augmentation {
		aug = pub.Bytes()
	}
	return (*blst.P1Affine)(sig).CoreVerify(true, (*blst.P2Affine)(pub), true, digest, true, scheme.SuiteG(1), aug)
}

func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, errors.New("blst: zero arguments")
	}
	acc := (*blst.P1Affine)(sigs[0]).Jacobian()
	for i := 1; i < len(sigs); i++ {
		acc.AddOrDoubleAffine((*blst.P1Affine)(sigs[1]))
	}
	return (*Signature)(acc.Affine()), nil
}

type PubDigestPair struct {
	Pub    *PublicKey
	Digest []byte
}

type pubMsgPair struct {
	*PubDigestPair
	scheme blst.Scheme
}

func (pair pubMsgPair) Public() *blst.P2Affine { return (*blst.P2Affine)(pair.Pub) }
func (pair pubMsgPair) Message() []byte        { return pair.Digest }
func (pair pubMsgPair) Augmentation() []byte {
	if pair.scheme == blst.Augmentation {
		return pair.Pub.Bytes()
	}
	return nil
}

type pubMsgPairs struct {
	pairs  []*PubDigestPair
	scheme blst.Scheme
}

func (pairs pubMsgPairs) Len() int { return len(pairs.pairs) }
func (pairs pubMsgPairs) Index(i int) blst.PkMsgPairG1 {
	return pubMsgPair{
		PubDigestPair: pairs.pairs[i],
		scheme:        pairs.scheme,
	}
}

func hasDuplicates(msgs [][]byte) bool {
	sort.Slice(msgs, func(i, j int) bool { return bytes.Compare(msgs[i], msgs[j]) < 0 })
	var prev []byte
	for _, m := range msgs {
		if prev != nil && bytes.Equal(prev, m) {
			return true
		}
		prev = m
	}
	return false
}

func (sig *Signature) AggregateVerify(items []*PubDigestPair, scheme blst.Scheme) error {
	msgs := make([][]byte, len(items))
	for i, itm := range items {
		msgs[i] = itm.Digest
	}
	if hasDuplicates(msgs) {
		return blst.ErrNotUnique
	}
	pairs := pubMsgPairs{
		pairs:  items,
		scheme: scheme,
	}
	return (*blst.P1Affine)(sig).CoreAggregateVerify(true, pairs, true, true, scheme.SuiteG(2))
}
