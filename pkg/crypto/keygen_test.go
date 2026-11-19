package crypto

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"testing"
)

func TestNewRSAKeyPairGenerator(t *testing.T) {
	testCases := []struct {
		name    string
		bits    int
		want    KeyPairGenerator
		wantErr bool
	}{
		{
			name: "2048",
			bits: 2048,
			want: rsaKeyPairGenerator{bits: 2048},
		},
		{
			name: "size between conventional sizes",
			bits: 2050,
			want: rsaKeyPairGenerator{bits: 2050},
		},
		{
			name: "8192",
			bits: 8192,
			want: rsaKeyPairGenerator{bits: 8192},
		},
		{
			name:    "below floor",
			bits:    1024,
			wantErr: true,
		},
		{
			name:    "zero",
			bits:    0,
			wantErr: true,
		},
		{
			name:    "negative",
			bits:    -2048,
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewRSAKeyPairGenerator(tc.bits)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewRSAKeyPairGenerator(%d) = %+v, want error", tc.bits, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRSAKeyPairGenerator(%d) error = %v", tc.bits, err)
			}
			if got != tc.want {
				t.Errorf("NewRSAKeyPairGenerator(%d) = %+v, want %+v", tc.bits, got, tc.want)
			}
		})
	}
}

func TestNewECDSAKeyPairGenerator(t *testing.T) {
	testCases := []struct {
		name    string
		curve   ECDSACurve
		want    KeyPairGenerator
		wantErr bool
	}{
		{
			name:  "P256",
			curve: P256,
			want:  ecdsaKeyPairGenerator{curve: P256},
		},
		{
			name:  "P384",
			curve: P384,
			want:  ecdsaKeyPairGenerator{curve: P384},
		},
		{
			name:  "P521",
			curve: P521,
			want:  ecdsaKeyPairGenerator{curve: P521},
		},
		{
			name:    "unknown curve",
			curve:   "P224",
			wantErr: true,
		},
		{
			name:    "empty curve",
			curve:   "",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewECDSAKeyPairGenerator(tc.curve)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewECDSAKeyPairGenerator(%q) = %+v, want error", tc.curve, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewECDSAKeyPairGenerator(%q) error = %v", tc.curve, err)
			}
			if got != tc.want {
				t.Errorf("NewECDSAKeyPairGenerator(%q) = %+v, want %+v", tc.curve, got, tc.want)
			}
		})
	}
}

// TestRSAKeyPairGeneratorEnforcesFloor covers generators that bypass the
// constructor: GenerateKeyPair must refuse to produce a key below the floor,
// including for the zero value.
func TestRSAKeyPairGeneratorEnforcesFloor(t *testing.T) {
	testCases := []struct {
		name string
		g    rsaKeyPairGenerator
	}{
		{
			name: "zero value",
			g:    rsaKeyPairGenerator{},
		},
		{
			name: "1024 bits",
			g:    rsaKeyPairGenerator{bits: 1024},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.g.GenerateKeyPair(); err == nil {
				t.Fatal("GenerateKeyPair() error = nil, want error")
			}
		})
	}
}

func TestRSAKeyPairGeneratorGeneratesRequestedSize(t *testing.T) {
	g, err := NewRSAKeyPairGenerator(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", pub)
	}
	if rsaPub.N.BitLen() != 2048 {
		t.Errorf("key size = %d, want 2048", rsaPub.N.BitLen())
	}
	if _, ok := priv.(stdcrypto.Signer); !ok {
		t.Errorf("private key type %T does not implement crypto.Signer", priv)
	}
}
