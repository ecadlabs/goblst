package minsig

import (
	"crypto/rand"
	"io"
	"testing"

	blst "github.com/ecadlabs/goblst"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

func TestSignVerifyBasic(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, priv)

	pub := priv.PublicKey()
	require.NotNil(t, pub)
	msg := []byte("Nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura, ché la diritta via era smarrita.")
	digest := blake2b.Sum256(msg)

	sig := Sign(priv, digest[:], blst.Basic)
	require.NotNil(t, sig)
	require.NoError(t, sig.Verify(pub, digest[:], blst.Basic))
}

func TestSignVerifyAug(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, priv)

	pub := priv.PublicKey()
	require.NotNil(t, pub)
	msg := []byte("Ahi quanto a dir qual era è cosa dura esta selva selvaggia e aspra e forte che nel pensier rinova la paura!")
	digest := blake2b.Sum256(msg)

	sig := Sign(priv, digest[:], blst.Augmentation)
	require.NotNil(t, sig)
	require.NoError(t, sig.Verify(pub, digest[:], blst.Augmentation))
}

const numSig = 10

func TestAggregate(t *testing.T) {
	pairs := make([]*PubDigestPair, numSig)
	sigs := make([]*Signature, numSig)

	for i := 0; i < numSig; i++ {
		priv, err := GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, priv)

		pub := priv.PublicKey()
		require.NotNil(t, pub)
		var buf [32]byte
		_, err = io.ReadFull(rand.Reader, buf[:])
		require.NoError(t, err)
		digest := blake2b.Sum256(buf[:])

		sig := Sign(priv, digest[:], blst.Basic)
		require.NotNil(t, sig)

		pairs[i] = &PubDigestPair{
			Pub:    pub,
			Digest: digest[:],
		}
		sigs[i] = sig
	}

	aggregated, err := AggregateSignatures(sigs)
	require.NoError(t, err)

	require.NoError(t, aggregated.AggregateVerify(pairs, blst.Basic))
}
