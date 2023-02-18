package goblst

// #cgo CFLAGS: -I${SRCDIR}/blst/bindings -I${SRCDIR}/blst/build -I${SRCDIR}/blst/src -D__BLST_CGO__ -fno-builtin-memcpy -fno-builtin-memset
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// #cgo mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__
// #include "blst.h"
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"unsafe"
)

type scalar = C.blst_scalar
type fp = C.blst_fp
type fp2 = C.blst_fp2
type fp12 = C.blst_fp12
type p1 = C.blst_p1
type p2 = C.blst_p2
type p1Affine = C.blst_p1_affine
type p2Affine = C.blst_p2_affine
type pairing = C.blst_pairing

type Scalar scalar
type Fp fp
type Fp2 fp2
type Fp12 fp12
type P1 p1
type P2 p2
type P1Affine p1Affine
type P2Affine p2Affine

const (
	P1ByteLength     = 48
	P2ByteLength     = 96
	ScalarByteLength = 32
)

type Error int

const (
	ErrSuccess          Error = Error(C.BLST_SUCCESS)
	ErrBadEncoding      Error = Error(C.BLST_BAD_ENCODING)
	ErrPointNotOnCurve  Error = Error(C.BLST_POINT_NOT_ON_CURVE)
	ErrPointNotInGroup  Error = Error(C.BLST_POINT_NOT_IN_GROUP)
	ErrAggrTypeMismatch Error = Error(C.BLST_AGGR_TYPE_MISMATCH)
	ErrVerifyFail       Error = Error(C.BLST_VERIFY_FAIL)
	ErrPkIsInfinity     Error = Error(C.BLST_PK_IS_INFINITY)
	ErrBadScalar        Error = Error(C.BLST_BAD_SCALAR)
)

var ErrNotUnique = errors.New("messages are not unique")

func (e Error) Error() string {
	var msg string
	switch e {
	case ErrSuccess:
		msg = "success"
	case ErrBadEncoding:
		msg = "bad encoding"
	case ErrPointNotOnCurve:
		msg = "point not on curve"
	case ErrPointNotInGroup:
		msg = "point not in group"
	case ErrAggrTypeMismatch:
		msg = "aggr type mismatch"
	case ErrVerifyFail:
		msg = "verify fail"
	case ErrPkIsInfinity:
		msg = "pk is infinity"
	case ErrBadScalar:
		msg = "bad scalar"
	default:
		msg = strconv.FormatInt(int64(e), 10)
	}
	return "blst: " + msg
}

func GenerateKey(ikm []byte) (*Scalar, error) {
	if len(ikm) < 32 {
		return nil, fmt.Errorf("blst: key material is too short: %d", len(ikm))
	}
	var s scalar
	C.blst_keygen(&s, (*C.uint8_t)(&ikm[0]), C.size_t(len(ikm)), nil, 0)
	return (*Scalar)(&s), nil
}

func ScalarFromBytes(data []byte) (*Scalar, error) {
	if len(data) != ScalarByteLength {
		return nil, fmt.Errorf("blst: wrong scalar byte length: %d", len(data))
	}
	var out scalar
	C.blst_scalar_from_lendian(&out, (*C.uint8_t)(&data[0]))
	return (*Scalar)(&out), nil
}

func (s *Scalar) P1() *P1 {
	var p p1
	C.blst_sk_to_pk_in_g1(&p, (*scalar)(s))
	return (*P1)(&p)
}

func (s *Scalar) P2() *P2 {
	var p p2
	C.blst_sk_to_pk_in_g2(&p, (*scalar)(s))
	return (*P2)(&p)
}

func (s *Scalar) P1Affine() *P1Affine {
	var p p1Affine
	C.blst_sk_to_pk2_in_g1(nil, &p, (*scalar)(s))
	return (*P1Affine)(&p)
}

func (s *Scalar) P2Affine() *P2Affine {
	var p p2Affine
	C.blst_sk_to_pk2_in_g2(nil, &p, (*scalar)(s))
	return (*P2Affine)(&p)
}

func (s *Scalar) Bytes() []byte {
	var out [ScalarByteLength]byte
	C.blst_lendian_from_scalar((*C.uint8_t)(&out[0]), (*scalar)(s))
	return out[:]
}

func (s *Scalar) Equal(x *Scalar) bool {
	return bytes.Equal(
		C.GoBytes(unsafe.Pointer(&(*scalar)(s).b[0]), C.int(len((*scalar)(s).b))),
		C.GoBytes(unsafe.Pointer(&(*scalar)(x).b[0]), C.int(len((*scalar)(x).b))),
	)
}

func (s *Scalar) SignInG1(hash *P2) *P2 {
	var sig p2
	C.blst_sign_pk_in_g1(&sig, (*p2)(hash), (*scalar)(s))
	return (*P2)(&sig)
}

func (s *Scalar) SignInG2(hash *P1) *P1 {
	var sig p1
	C.blst_sign_pk_in_g2(&sig, (*p1)(hash), (*scalar)(s))
	return (*P1)(&sig)
}

func (s *Scalar) SignInG1Affine(hash *P2) *P2Affine {
	var sig p2Affine
	C.blst_sign_pk2_in_g1(nil, &sig, (*p2)(hash), (*scalar)(s))
	return (*P2Affine)(&sig)
}

func (s *Scalar) SignInG2Affine(hash *P1) *P1Affine {
	var sig p1Affine
	C.blst_sign_pk2_in_g2(nil, &sig, (*p1)(hash), (*scalar)(s))
	return (*P1Affine)(&sig)
}

func DecompressP1Affine(compressed []byte) (*P1Affine, error) {
	if len(compressed) != P1ByteLength {
		return nil, fmt.Errorf("wrong compressed p1 byte length: %d", len(compressed))
	}
	var out p1Affine
	if err := C.blst_p1_uncompress(&out, (*C.uint8_t)(&compressed[0])); err != C.BLST_SUCCESS {
		return nil, Error(err)
	}
	return (*P1Affine)(&out), nil
}

func (p *P1Affine) Compress() []byte {
	var out [P1ByteLength]byte
	C.blst_p1_affine_compress((*C.uint8_t)(&out[0]), (*p1Affine)(p))
	return out[:]
}

func (p *P1Affine) Jacobian() *P1 {
	var out p1
	C.blst_p1_from_affine(&out, (*p1Affine)(p))
	return (*P1)(&out)
}

func (p *P1Affine) Equal(x *P1Affine) bool {
	return bool(C.blst_p1_affine_is_equal((*p1Affine)(p), (*p1Affine)(x)))
}

func (p *P1Affine) IsInf() bool {
	return bool(C.blst_p1_affine_is_inf((*p1Affine)(p)))
}

func (p *P1Affine) IsInG1() bool {
	return bool(C.blst_p1_affine_in_g1((*p1Affine)(p)))
}

func (p *P1Affine) IsOnCurve() bool {
	return bool(C.blst_p1_affine_on_curve((*p1Affine)(p)))
}

type PkMsgPairsG1 interface {
	Len() int
	Index(int) PkMsgPairG1
}

type PkMsgPairG1 interface {
	Public() *P2Affine
	Message() []byte
	Augmentation() []byte
}

type pkMsgPairG1 struct {
	Pub *P2Affine
	Msg []byte
	Aug []byte
}

func (pair *pkMsgPairG1) Public() *P2Affine    { return pair.Pub }
func (pair *pkMsgPairG1) Message() []byte      { return pair.Msg }
func (pair *pkMsgPairG1) Augmentation() []byte { return pair.Aug }

type pkMsgPairsG1 []pkMsgPairG1

func (pairs pkMsgPairsG1) Len() int                { return len(pairs) }
func (pairs pkMsgPairsG1) Index(i int) PkMsgPairG1 { return &pairs[i] }

func (sig *P1Affine) CoreAggregateVerify(validate_sig bool, items PkMsgPairsG1, validate_pub bool, hash bool, suite []byte) error {
	if items.Len() == 0 {
		return errors.New("blst: zero arguments")
	}
	pairings := make([]*Pairing, items.Len())
	for i := range pairings {
		pairings[i] = NewPairing(hash, suite)
	}

	if err := runInParallel(items.Len(), func(i int) error {
		itm := items.Index(i)
		if err := pairings[i].AggregateInG2(itm.Public(), validate_pub, nil, false, itm.Message(), itm.Augmentation()); err != nil {
			return err
		}
		pairings[i].Commit()
		return nil
	}); err != nil {
		return err
	}

	gtsig := AggregatedInG1(sig)
	acc := pairings[0]
	for i := 1; i < len(pairings); i++ {
		if err := acc.Merge(pairings[i]); err != nil {
			return err
		}
	}

	switch {
	case validate_sig && !sig.IsInG1():
		return ErrPointNotInGroup
	case !acc.FinalVerify(gtsig):
		return ErrVerifyFail
	default:
		return nil
	}
}

func (sig *P1Affine) CoreVerify(validate_sig bool, pub *P2Affine, validate_pub bool, msg []byte, hash bool, suite []byte, aug []byte) error {
	return sig.CoreAggregateVerify(validate_sig, pkMsgPairsG1{
		pkMsgPairG1{
			Pub: pub,
			Msg: msg,
			Aug: aug,
		},
	}, validate_pub, hash, suite)
}

func DecompressP2Affine(compressed []byte) (*P2Affine, error) {
	if len(compressed) != P2ByteLength {
		return nil, fmt.Errorf("wrong compressed p2 byte length: %d", len(compressed))
	}
	var out p2Affine
	if err := C.blst_p2_uncompress(&out, (*C.uint8_t)(&compressed[0])); err != C.BLST_SUCCESS {
		return nil, Error(err)
	}
	return (*P2Affine)(&out), nil
}

func (p *P2Affine) Jacobian() *P2 {
	var out p2
	C.blst_p2_from_affine(&out, (*p2Affine)(p))
	return (*P2)(&out)
}

func (p *P2Affine) Compress() []byte {
	var out [P2ByteLength]byte
	C.blst_p2_affine_compress((*C.uint8_t)(&out[0]), (*p2Affine)(p))
	return out[:]
}

func (p *P2Affine) Equal(x *P2Affine) bool {
	return bool(C.blst_p2_affine_is_equal((*p2Affine)(p), (*p2Affine)(x)))
}

func (p *P2Affine) IsInf() bool {
	return bool(C.blst_p2_affine_is_inf((*p2Affine)(p)))
}

func (p *P2Affine) IsInG2() bool {
	return bool(C.blst_p2_affine_in_g2((*p2Affine)(p)))
}

func (p *P2Affine) IsOnCurve() bool {
	return bool(C.blst_p2_affine_on_curve((*p2Affine)(p)))
}

type PkMsgPairsG2 interface {
	Len() int
	Index(int) PkMsgPairG2
}

type PkMsgPairG2 interface {
	Public() *P1Affine
	Message() []byte
	Augmentation() []byte
}

type pkMsgPairG2 struct {
	Pub *P1Affine
	Msg []byte
	Aug []byte
}

func (pair *pkMsgPairG2) Public() *P1Affine    { return pair.Pub }
func (pair *pkMsgPairG2) Message() []byte      { return pair.Msg }
func (pair *pkMsgPairG2) Augmentation() []byte { return pair.Aug }

type pkMsgPairsG2 []pkMsgPairG2

func (pairs pkMsgPairsG2) Len() int                { return len(pairs) }
func (pairs pkMsgPairsG2) Index(i int) PkMsgPairG2 { return &pairs[i] }

func (sig *P2Affine) CoreAggregateVerify(validate_sig bool, items PkMsgPairsG2, validate_pub bool, hash bool, suite []byte) error {
	if items.Len() == 0 {
		return errors.New("blst: zero arguments")
	}
	pairings := make([]*Pairing, items.Len())
	for i := range pairings {
		pairings[i] = NewPairing(hash, suite)
	}

	if err := runInParallel(items.Len(), func(i int) error {
		itm := items.Index(i)
		if err := pairings[i].AggregateInG1(itm.Public(), validate_pub, nil, false, itm.Message(), itm.Augmentation()); err != nil {
			return err
		}
		pairings[i].Commit()
		return nil
	}); err != nil {
		return err
	}

	gtsig := AggregatedInG2(sig)
	acc := pairings[0]
	for i := 1; i < len(pairings); i++ {
		if err := acc.Merge(pairings[i]); err != nil {
			return err
		}
	}

	switch {
	case validate_sig && !sig.IsInG2():
		return ErrPointNotInGroup
	case !acc.FinalVerify(gtsig):
		return ErrVerifyFail
	default:
		return nil
	}
}

func (sig *P2Affine) CoreVerify(validate_sig bool, pub *P1Affine, validate_pub bool, msg []byte, hash bool, suite []byte, aug []byte) error {
	return sig.CoreAggregateVerify(validate_sig, pkMsgPairsG2{
		pkMsgPairG2{
			Pub: pub,
			Msg: msg,
			Aug: aug,
		},
	}, validate_pub, hash, suite)
}

func (p *P1) Affine() *P1Affine {
	var out p1Affine
	C.blst_p1_to_affine(&out, (*p1)(p))
	return (*P1Affine)(&out)
}

func (p *P1) Compress() []byte {
	var out [P1ByteLength]byte
	C.blst_p1_compress((*C.uint8_t)(&out[0]), (*p1)(p))
	return out[:]
}

func (p *P1) Equal(x *P1) bool {
	return bool(C.blst_p1_is_equal((*p1)(p), (*p1)(x)))
}

func (p *P1) IsInf() bool {
	return bool(C.blst_p1_is_inf((*p1)(p)))
}

func (p *P1) IsInG1() bool {
	return bool(C.blst_p1_in_g1((*p1)(p)))
}

func (p *P1) IsOnCurve() bool {
	return bool(C.blst_p1_on_curve((*p1)(p)))
}

func (p *P1) AddOrDoubleAffine(other *P1Affine) {
	C.blst_p1_add_or_double_affine((*p1)(p), (*p1)(p), (*p1Affine)(other))
}

func HashToP1(digest, suite, aug []byte) *P1 {
	var (
		q p1
		a *byte
	)
	if len(aug) != 0 {
		a = &aug[0]
	}
	C.blst_hash_to_g1(&q, (*C.uint8_t)(&digest[0]), C.size_t(len(digest)),
		(*C.uint8_t)(&suite[0]), C.size_t(len(suite)),
		(*C.uint8_t)(a), C.size_t(len(aug)))
	return (*P1)(&q)
}

func EncodeToP1(digest, suite, aug []byte) *P1 {
	var (
		q p1
		a *byte
	)
	if len(aug) != 0 {
		a = &aug[0]
	}
	C.blst_encode_to_g1(&q, (*C.uint8_t)(&digest[0]), C.size_t(len(digest)),
		(*C.uint8_t)(&suite[0]), C.size_t(len(suite)),
		(*C.uint8_t)(a), C.size_t(len(aug)))
	return (*P1)(&q)
}

func (p *P2) Affine() *P2Affine {
	var out p2Affine
	C.blst_p2_to_affine(&out, (*p2)(p))
	return (*P2Affine)(&out)
}

func (p *P2) Compress() []byte {
	var out [P2ByteLength]byte
	C.blst_p2_compress((*C.uint8_t)(&out[0]), (*p2)(p))
	return out[:]
}

func (p *P2) Equal(x *P2) bool {
	return bool(C.blst_p2_is_equal((*p2)(p), (*p2)(x)))
}

func (p *P2) IsInf() bool {
	return bool(C.blst_p2_is_inf((*p2)(p)))
}

func (p *P2) IsInG2() bool {
	return bool(C.blst_p2_in_g2((*p2)(p)))
}

func (p *P2) IsOnCurve() bool {
	return bool(C.blst_p2_on_curve((*p2)(p)))
}

func (p *P2) AddOrDoubleAffine(other *P2Affine) {
	C.blst_p2_add_or_double_affine((*p2)(p), (*p2)(p), (*p2Affine)(other))
}

func HashToP2(digest, suite, aug []byte) *P2 {
	var (
		q p2
		a *byte
	)
	if len(aug) != 0 {
		a = &aug[0]
	}
	C.blst_hash_to_g2(&q, (*C.uint8_t)(&digest[0]), C.size_t(len(digest)),
		(*C.uint8_t)(&suite[0]), C.size_t(len(suite)),
		(*C.uint8_t)(a), C.size_t(len(aug)))
	return (*P2)(&q)
}

func EncodeToP2(digest, suite, aug []byte) *P2 {
	var (
		q p2
		a *byte
	)
	if len(aug) != 0 {
		a = &aug[0]
	}
	C.blst_encode_to_g2(&q, (*C.uint8_t)(&digest[0]), C.size_t(len(digest)),
		(*C.uint8_t)(&suite[0]), C.size_t(len(suite)),
		(*C.uint8_t)(a), C.size_t(len(aug)))
	return (*P2)(&q)
}

// aligned memory
type Pairing struct {
	p []uintptr
}

func (p Pairing) ptr() *pairing {
	return (*pairing)(unsafe.Pointer(&p.p[0]))
}

func NewPairing(hash bool, suite []byte) *Pairing {
	size := int(C.blst_pairing_sizeof())
	p := Pairing{
		p: make([]uintptr, (size+int(unsafe.Sizeof(uintptr(0)))-1)/int(unsafe.Sizeof(uintptr(0)))),
	}
	C.blst_pairing_init(p.ptr(), C.bool(hash), (*C.uint8_t)(&suite[0]), C.size_t(len(suite)))
	return &p
}

func (p *Pairing) AggregateInG1(pub *P1Affine, validate_pub bool, sig *P2Affine, validate_sig bool, msg, aug []byte) error {
	var a *byte
	if len(aug) != 0 {
		a = &aug[0]
	}
	if err := C.blst_pairing_chk_n_aggr_pk_in_g1(p.ptr(),
		(*p1Affine)(pub),
		C.bool(validate_pub),
		(*p2Affine)(sig),
		C.bool(validate_sig),
		(*C.uint8_t)(&msg[0]), C.size_t(len(msg)),
		(*C.uint8_t)(a), C.size_t(len(aug))); err != C.BLST_SUCCESS {
		return Error(err)
	}
	return nil
}

func (p *Pairing) AggregateInG2(pub *P2Affine, validate_pub bool, sig *P1Affine, validate_sig bool, msg, aug []byte) error {
	var a *byte
	if len(aug) != 0 {
		a = &aug[0]
	}
	if err := C.blst_pairing_chk_n_aggr_pk_in_g2(p.ptr(),
		(*p2Affine)(pub),
		C.bool(validate_pub),
		(*p1Affine)(sig),
		C.bool(validate_sig),
		(*C.uint8_t)(&msg[0]), C.size_t(len(msg)),
		(*C.uint8_t)(a), C.size_t(len(aug))); err != C.BLST_SUCCESS {
		return Error(err)
	}
	return nil
}

func (p *Pairing) Commit() {
	C.blst_pairing_commit(p.ptr())
}

func (p *Pairing) Merge(other *Pairing) error {
	if err := C.blst_pairing_merge(p.ptr(), other.ptr()); err != C.BLST_SUCCESS {
		return Error(err)
	}
	return nil
}

func (p *Pairing) FinalVerify(gtsig *Fp12) bool {
	return bool(C.blst_pairing_finalverify(p.ptr(), (*fp12)(gtsig)))
}

func AggregatedInG1(sig *P1Affine) *Fp12 {
	var out fp12
	C.blst_aggregated_in_g1(&out, (*p1Affine)(sig))
	return (*Fp12)(&out)
}

func AggregatedInG2(sig *P2Affine) *Fp12 {
	var out fp12
	C.blst_aggregated_in_g2(&out, (*p2Affine)(sig))
	return (*Fp12)(&out)
}
