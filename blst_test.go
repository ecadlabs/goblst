package goblst_test

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	blst "github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/goblst/minsig"
	"github.com/stretchr/testify/require"
)

func getRecords(file string) ([][][]byte, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	out := make([][][]byte, 0)
	s := bufio.NewScanner(fd)
	for s.Scan() {
		fields := strings.Split(s.Text(), " ")
		f := make([][]byte, len(fields))
		for i, field := range fields {
			data, err := hex.DecodeString(field)
			if err != nil {
				return nil, err
			}
			f[i] = data
		}
		out = append(out, f)
	}
	return out, s.Err()
}

func TestSignVectors(t *testing.T) {
	type testVectorFiles struct {
		group  string
		genKey func(ikm []byte) (crypto.Signer, error)
		verify func(pub crypto.PublicKey, message []byte, sig []byte, scheme blst.Scheme) error
		scheme blst.Scheme
		files  []string
	}

	testCases := []testVectorFiles{
		{
			group:  "sig_g2_basic",
			genKey: func(ikm []byte) (crypto.Signer, error) { return minpk.GenerateKeyFrom(ikm) },
			verify: func(pub crypto.PublicKey, message []byte, sig []byte, scheme blst.Scheme) error {
				s, err := minpk.SignatureFromBytes(sig)
				if err != nil {
					return err
				}
				return minpk.Verify(pub.(*minpk.PublicKey), message, s, scheme)
			},
			scheme: blst.Basic,
			files: []string{
				"sig_g2_basic_fips_186_3_B233_blst",
				"sig_g2_basic_fips_186_3_B283_blst",
				"sig_g2_basic_fips_186_3_B409_blst",
				"sig_g2_basic_fips_186_3_B571_blst",
				"sig_g2_basic_fips_186_3_K233_blst",
				"sig_g2_basic_fips_186_3_K409_blst",
				"sig_g2_basic_fips_186_3_K571_blst",
				"sig_g2_basic_fips_186_3_P224_blst",
				"sig_g2_basic_fips_186_3_P256_blst",
				"sig_g2_basic_fips_186_3_P384_blst",
				"sig_g2_basic_fips_186_3_P521_blst",
				"sig_g2_basic_rfc6979_blst",
			},
		},
		{
			group:  "sig_g2_aug",
			genKey: func(ikm []byte) (crypto.Signer, error) { return minpk.GenerateKeyFrom(ikm) },
			verify: func(pub crypto.PublicKey, message []byte, sig []byte, scheme blst.Scheme) error {
				s, err := minpk.SignatureFromBytes(sig)
				if err != nil {
					return err
				}
				return minpk.Verify(pub.(*minpk.PublicKey), message, s, scheme)
			},
			scheme: blst.Augmentation,
			files: []string{
				"sig_g2_aug_fips_186_3_B233_blst",
				"sig_g2_aug_fips_186_3_B283_blst",
				"sig_g2_aug_fips_186_3_B409_blst",
				"sig_g2_aug_fips_186_3_B571_blst",
				"sig_g2_aug_fips_186_3_K233_blst",
				"sig_g2_aug_fips_186_3_K409_blst",
				"sig_g2_aug_fips_186_3_K571_blst",
				"sig_g2_aug_fips_186_3_P224_blst",
				"sig_g2_aug_fips_186_3_P256_blst",
				"sig_g2_aug_fips_186_3_P384_blst",
				"sig_g2_aug_fips_186_3_P521_blst",
				"sig_g2_aug_rfc6979_blst",
			},
		},
		{
			group:  "sig_g1_basic",
			genKey: func(ikm []byte) (crypto.Signer, error) { return minsig.GenerateKeyFrom(ikm) },
			verify: func(pub crypto.PublicKey, message []byte, sig []byte, scheme blst.Scheme) error {
				s, err := minsig.SignatureFromBytes(sig)
				if err != nil {
					return err
				}
				return minsig.Verify(pub.(*minsig.PublicKey), message, s, scheme)
			},
			scheme: blst.Basic,
			files: []string{
				"sig_g1_basic_fips_186_3_B233_blst",
				"sig_g1_basic_fips_186_3_B283_blst",
				"sig_g1_basic_fips_186_3_B409_blst",
				"sig_g1_basic_fips_186_3_B571_blst",
				"sig_g1_basic_fips_186_3_K233_blst",
				"sig_g1_basic_fips_186_3_K409_blst",
				"sig_g1_basic_fips_186_3_K571_blst",
				"sig_g1_basic_fips_186_3_P224_blst",
				"sig_g1_basic_fips_186_3_P256_blst",
				"sig_g1_basic_fips_186_3_P384_blst",
				"sig_g1_basic_fips_186_3_P521_blst",
				"sig_g1_basic_rfc6979_blst",
			},
		},
		{
			group:  "sig_g1_aug",
			genKey: func(ikm []byte) (crypto.Signer, error) { return minsig.GenerateKeyFrom(ikm) },
			verify: func(pub crypto.PublicKey, message []byte, sig []byte, scheme blst.Scheme) error {
				s, err := minsig.SignatureFromBytes(sig)
				if err != nil {
					return err
				}
				return minsig.Verify(pub.(*minsig.PublicKey), message, s, scheme)
			},
			scheme: blst.Augmentation,
			files: []string{
				"sig_g1_aug_fips_186_3_B233_blst",
				"sig_g1_aug_fips_186_3_B283_blst",
				"sig_g1_aug_fips_186_3_B409_blst",
				"sig_g1_aug_fips_186_3_B571_blst",
				"sig_g1_aug_fips_186_3_K233_blst",
				"sig_g1_aug_fips_186_3_K409_blst",
				"sig_g1_aug_fips_186_3_K571_blst",
				"sig_g1_aug_fips_186_3_P224_blst",
				"sig_g1_aug_fips_186_3_P256_blst",
				"sig_g1_aug_fips_186_3_P384_blst",
				"sig_g1_aug_fips_186_3_P521_blst",
				"sig_g1_aug_rfc6979_blst",
			},
		},
	}

	for _, gr := range testCases {
		t.Run(gr.group, func(t *testing.T) {
			for _, file := range gr.files {
				t.Run(file, func(t *testing.T) {
					records, err := getRecords(filepath.Join("test_vectors", gr.group, file))
					require.NoError(t, err)

					for _, record := range records {
						msg, ikm, result := record[0], record[1], record[2]
						if len(ikm) < 32 {
							continue
						}
						priv, err := gr.genKey(ikm)
						require.NoError(t, err)
						require.NotNil(t, priv)

						sig, err := priv.Sign(nil, msg, gr.scheme)
						require.NoError(t, err)
						require.NotNil(t, sig)

						require.Equal(t, result, sig)

						require.NoError(t, gr.verify(priv.Public(), msg, sig, gr.scheme))
					}
				})
			}
		})
	}
}

func TestInvalidPub(t *testing.T) {
	t.Run("MinPk", func(t *testing.T) {
		keys := []string{
			"a4c9678ad327129f4388e7f7ff781fc8e98d181add820b79d15facdca422b3ee7fb20f7082a7f9b7c7915053191cb013",
			"97ae9b4dc6a05cda8bc833dfb983e41423d224bbf6954ce4721a50364a2b37643e18a276ce19b07b83a333f90e2de6c2",
			"b1be8c9f94c1435227b9a18fb57a6d9932c1670d16c514d2d9d67839cc0cc19afdcd114d6e06bf8eb8394061bf880bd4",
			"b173357ce7e2340dc64c6a5633e6800683fb0a6c0f4af92b383425bd76d915819252ac9459e79a1bae530ea0145338cb",
			"a53944773013669c2722949399322703c0b92d877e52b95e0309bdf286d8290314763d61952d6812da50c1826bcaf4c3",
			"8fd2557441f4076917ffe8dfb0e12270994351661600e72f48fe654198199f6cc625a041ce3c9b7c765b32cb53e77192",
		}

		for _, key := range keys {
			k, err := hex.DecodeString(key)
			require.NoError(t, err)
			pub, err := minpk.PublicKeyFromBytes(k)
			require.NoError(t, err)
			require.EqualError(t, pub.IsValid(), "blst: point not in group")
		}
	})
	t.Run("MinSig", func(t *testing.T) {
		keys := []string{
			"a7da246233ad216e60ee03070a0916154ae9f9dc23310c1191dfb4e277fc757f58a5cf5bdf7a9f322775143c37539cb90798205fd56217b682d5656f7ac7bc0da111dee59d3f863f1b040be659eda7941afb9f1bc5d0fe2beb5e2385e2cfe9ee",
			"b112717bbcd089ea99e8216eab455ea5cd462b0b3e3530303b83477f8e1bb7abca269fec10b3eb998f7f6fd1799d58ff11ed0a53bf75f91d2bf73d11bd52d061f401ac6a6ec0ef4a163e480bac85e75b97cb556f500057b9ef4b28bfe196791d",
			"86e5fa411047d9632c95747bea64d973757904c935ac0741b9eeefa2c7c4e439baf1d2c1e8633ba6c884ed9fdf1ffbdd129a32c046f355c5126254973115d6df32904498db6ca959d5bf1869f235be4c0e60fc334ed493f864476907cadfef2c",
			"88c83e90520a5ea31733cc01e3589e10b2ed755e2faade29199f97645fbf73f52b29297c22a3b1c4fcd3379bceeec832091df6fb3b9d23f04e8267fc41e578002484155562e70f488c2a4c6b11522c66736bc977755c257478f3022656abb630",
			"a25099811f52ad463c762197466c476a03951afdb3f0a457efa2b9475376652fba7b2d56f3184dad540a234d471c53a113203f73dd661694586c75d9c418d34cd16504356253e3ba4618f61cbee02880a43efeacb8f9fe1fdc84ceec4f780ba2",
			"990f5e1d200d1b9ab842c516ce50992730917a8b2e95ee1a4b830d7d9507c6846ace7a0eed8831a8d1f1e233cd24581215fe8fe85a99f4ca3fe046dba8ac6377fc3c10d73fa94b25c2d534d7a587a507b498754a2534cd85777b2a7f2978eec6",
			"a29415562a1d18b11ec8ab2e0b347a9417f9e904cf25f9b1dc40f235507814371fb4568cc1070a0b8c7baf39e0039d1e0b49d4352b095883ccc262e23d8651c49c39c06d0a920d40b2765d550a78c4c1940c8a2b6843a0063402c169f079f0ae",
			"8a257ed6d95cb226c3eb57218bd075ba27164fc1b972c4230ee70c7b81c89d38253ccf7ed2896aa5eb3d9fd6021fac000e368080e705f2a65c919539e2d28e6dd1117296b4210fd56db8d96891f8586bd333e9c47f838ed436659a1dafaee16c",
		}

		for _, key := range keys {
			k, err := hex.DecodeString(key)
			require.NoError(t, err)
			pub, err := minsig.PublicKeyFromBytes(k)
			require.NoError(t, err)
			require.EqualError(t, pub.IsValid(), "blst: point not in group")
		}
	})
}

func TestInvalidPoint(t *testing.T) {
	p1s := []string{
		"a4c9678ad327129f4388e7f7ff781fc8e98d181add820b79d15facdca422b3ee7fb20f7082a7f9b7c7915053191cb013",
		"97ae9b4dc6a05cda8bc833dfb983e41423d224bbf6954ce4721a50364a2b37643e18a276ce19b07b83a333f90e2de6c2",
		"b1be8c9f94c1435227b9a18fb57a6d9932c1670d16c514d2d9d67839cc0cc19afdcd114d6e06bf8eb8394061bf880bd4",
		"b173357ce7e2340dc64c6a5633e6800683fb0a6c0f4af92b383425bd76d915819252ac9459e79a1bae530ea0145338cb",
		"a53944773013669c2722949399322703c0b92d877e52b95e0309bdf286d8290314763d61952d6812da50c1826bcaf4c3",
		"8fd2557441f4076917ffe8dfb0e12270994351661600e72f48fe654198199f6cc625a041ce3c9b7c765b32cb53e77192",
	}
	p2s := []string{
		"a7da246233ad216e60ee03070a0916154ae9f9dc23310c1191dfb4e277fc757f58a5cf5bdf7a9f322775143c37539cb90798205fd56217b682d5656f7ac7bc0da111dee59d3f863f1b040be659eda7941afb9f1bc5d0fe2beb5e2385e2cfe9ee",
		"b112717bbcd089ea99e8216eab455ea5cd462b0b3e3530303b83477f8e1bb7abca269fec10b3eb998f7f6fd1799d58ff11ed0a53bf75f91d2bf73d11bd52d061f401ac6a6ec0ef4a163e480bac85e75b97cb556f500057b9ef4b28bfe196791d",
		"86e5fa411047d9632c95747bea64d973757904c935ac0741b9eeefa2c7c4e439baf1d2c1e8633ba6c884ed9fdf1ffbdd129a32c046f355c5126254973115d6df32904498db6ca959d5bf1869f235be4c0e60fc334ed493f864476907cadfef2c",
		"88c83e90520a5ea31733cc01e3589e10b2ed755e2faade29199f97645fbf73f52b29297c22a3b1c4fcd3379bceeec832091df6fb3b9d23f04e8267fc41e578002484155562e70f488c2a4c6b11522c66736bc977755c257478f3022656abb630",
		"a25099811f52ad463c762197466c476a03951afdb3f0a457efa2b9475376652fba7b2d56f3184dad540a234d471c53a113203f73dd661694586c75d9c418d34cd16504356253e3ba4618f61cbee02880a43efeacb8f9fe1fdc84ceec4f780ba2",
		"990f5e1d200d1b9ab842c516ce50992730917a8b2e95ee1a4b830d7d9507c6846ace7a0eed8831a8d1f1e233cd24581215fe8fe85a99f4ca3fe046dba8ac6377fc3c10d73fa94b25c2d534d7a587a507b498754a2534cd85777b2a7f2978eec6",
		"a29415562a1d18b11ec8ab2e0b347a9417f9e904cf25f9b1dc40f235507814371fb4568cc1070a0b8c7baf39e0039d1e0b49d4352b095883ccc262e23d8651c49c39c06d0a920d40b2765d550a78c4c1940c8a2b6843a0063402c169f079f0ae",
		"8a257ed6d95cb226c3eb57218bd075ba27164fc1b972c4230ee70c7b81c89d38253ccf7ed2896aa5eb3d9fd6021fac000e368080e705f2a65c919539e2d28e6dd1117296b4210fd56db8d96891f8586bd333e9c47f838ed436659a1dafaee16c",
	}

	t.Run("MinPk", func(t *testing.T) {
		t.Run("Pk", func(t *testing.T) {
			for _, key := range p1s {
				k, err := hex.DecodeString(key)
				require.NoError(t, err)
				pub, err := minpk.PublicKeyFromBytes(k)
				require.NoError(t, err)
				require.EqualError(t, pub.IsValid(), "blst: point not in group")
			}
		})
		t.Run("Sig", func(t *testing.T) {
			for _, sig := range p2s {
				s, err := hex.DecodeString(sig)
				require.NoError(t, err)
				pub, err := minpk.SignatureFromBytes(s)
				require.NoError(t, err)
				require.EqualError(t, pub.IsValid(), "blst: point not in group")
			}
		})
	})
	t.Run("MinSig", func(t *testing.T) {
		t.Run("Pk", func(t *testing.T) {
			for _, key := range p2s {
				k, err := hex.DecodeString(key)
				require.NoError(t, err)
				pub, err := minsig.PublicKeyFromBytes(k)
				require.NoError(t, err)
				require.EqualError(t, pub.IsValid(), "blst: point not in group")
			}
		})
		t.Run("Sig", func(t *testing.T) {
			for _, sig := range p1s {
				s, err := hex.DecodeString(sig)
				require.NoError(t, err)
				pub, err := minsig.SignatureFromBytes(s)
				require.NoError(t, err)
				require.EqualError(t, pub.IsValid(), "blst: point not in group")
			}
		})
	})
}
